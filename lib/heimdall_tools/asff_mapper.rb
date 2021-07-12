require 'json'
require 'csv'
require 'heimdall_tools/hdf'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

AWS_CONFIG_MAPPING_FILE = File.join(RESOURCE_DIR, 'aws-config-mapping.csv')

IMPACT_MAPPING = {
  CRITICAL: 0.9,
  HIGH: 0.7,
  MEDIUM: 0.5,
  LOW: 0.3,
  INFORMATIONAL: 0.0
}.freeze

DEFAULT_NIST_TAG = %w{SA-11 RA-5}.freeze

INSPEC_INPUTS_MAPPING = {
  string: 'String',
  numeric: 'Numeric',
  regexp: 'Regexp',
  array: 'Array',
  hash: 'Hash',
  boolean: 'Boolean',
  any: 'Any'
}.freeze

# Loading spinner sign
$spinner = Enumerator.new do |e|
  loop do
    e.yield '|'
    e.yield '/'
    e.yield '-'
    e.yield '\\'
  end
end

module HeimdallTools
  class ASFFMapper
    # the optional arguments are derived from AWS cli commands (get-enabled-standards and describe-standards) and probably only work AWS ASFF files
    def initialize(asff_json, enabled_standards_json = nil, standards_json_array = nil)
      begin
        @aws_config_mapping = parse_mapper
      rescue StandardError => e
        raise "Invalid AWS Config mapping file:\nException: #{e}"
      end

      begin
        asff_required_keys = %w(AwsAccountId CreatedAt Description GeneratorId Id ProductArn Resources SchemaVersion Severity Title Types UpdatedAt)
        @report = JSON.parse(asff_json)
        if @report.length == 1 && @report.member?('Findings') && @report['Findings'].each { |finding| asff_required_keys.difference(finding.keys).none? }.all?
          # ideal case that is spec compliant
          # might need to ensure that the file is utf-8 encoded and remove a BOM if one exists
        elsif asff_required_keys.difference(@report.keys).none?
          # individual finding so have to add wrapping array
          @report = { 'Findings' => [@report] }
        else
          raise "Not a findings file nor an individual finding"
        end

        enabled = JSON.parse(enabled_standards_json) unless enabled_standards_json.nil?
        standards_array = standards_json_array.map { |j| JSON.parse(j) } unless standards_json_array.nil?
        @standards = enabled['StandardsSubscriptions'].to_h { |s| [s['StandardsSubscriptionArn'], standards_array.find { |st| st['Controls'][0]['StandardsControlArn'].include?(s['StandardsSubscriptionArn'].gsub(':subscription', ':control')) }] }.compact unless enabled.nil?

      rescue StandardError => e
        raise "Invalid ASFF file provided:\nException: #{e}"
      end
    end

    def parse_mapper
      csv_data = CSV.read(AWS_CONFIG_MAPPING_FILE, { encoding: 'UTF-8', headers: true, header_converters: :symbol })
      csv_data.map(&:to_hash)
    end

    def create_attribute(name, value, required = nil, sensitive = nil, type = nil)
      { name: name, options: { value: value, required: required, sensitive: sensitive, type: type }.compact }
    end

    def extract_scaninfo
      info = {}
      begin
        info['name'] = 'AWS Security Finding Format'
        info['title'] = "ASFF findings"
        info
      rescue StandardError => e
        raise "Error extracting report info from ASFF file:\nException: #{e}"
      end
    end

    # default value unless it comes from aws and has a aws config rule
    def nist_tag(detail)
      entries = detail.member?('ProductFields') && detail['ProductFields'].member?('RelatedAWSResources:0/type') && detail['ProductFields']['RelatedAWSResources:0/type'] == 'AWS::Config::ConfigRule' && detail['ProductFields'].member?('RelatedAWSResources:0/name') ? @aws_config_mapping.select { |rule| detail['ProductFields']['RelatedAWSResources:0/name'].include? rule[:awsconfigrulename] } : {}
      tags = entries.map { |rule| rule[:nistid].split('|') }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def impact(detail)
      # there can be findings listed that are intentionally ignored due to the underlying control being superceded by a control from a different standard
      if detail.member?('Workflow') && detail['Workflow'].member?('Status') && detail['Workflow']['Status'] == 'SUPPRESSED'
        IMPACT_MAPPING[:INFORMATIONAL]
      elsif @standards.nil? || !detail.member?('ProductFields') || !(detail['ProductFields'].member?('StandardsSubscriptionArn') || detail['ProductFields'].member?('StandardsGuideSubscriptionArn'))
        # severity is required, but can be either 'label' or 'normalized' internally with 'label' being preferred.  other values can be in here too such as the original severity rating.
        if detail['Severity'].key?('Label')
          severity = detail['Severity']['Label']
          # asff file does not contain accurate severity information - when additional context, i.e. standards, is not provided, set informational to medium.
          if severity == 'INFORMATIONAL'
            IMPACT_MAPPING[:MEDIUM]
          else
            IMPACT_MAPPING[severity.to_sym]
          end
        else
          detail['Severity']['Normalized']/100.0
        end
      else
        IMPACT_MAPPING[@standards[detail['ProductFields'][detail['ProductFields'].member?('StandardsSubscriptionArn') ? 'StandardsSubscriptionArn' : 'StandardsGuideSubscriptionArn']]['Controls'].find { |c| c['StandardsControlArn'] == detail['ProductFields']['StandardsControlArn'] }['SeverityRating'].to_sym]
      end
    end

    def desc_tags(data, label)
      { data: data || NA_STRING, label: label || NA_STRING }
    end

    # requires compliance->status attribute to be there - spec says it's optional
    def findings(detail)
      finding = {}
      if detail.key?('Compliance') && detail['Compliance'].key?('Status')
        case detail['Compliance']['Status']
        when 'PASSED'
          finding['status'] = 'passed'
          finding['message'] = detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") unless !detail['Compliance'].key?('StatusReasons')
        when 'WARNING'
          finding['status'] = 'skipped'
          finding['skip_message'] = detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") unless !detail['Compliance'].key?('StatusReasons')
        when 'FAILED'
          finding['status'] = 'failed'
          finding['message'] = detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") unless !detail['Compliance'].key?('StatusReasons')
        when 'NOT_AVAILABLE'
          finding['status'] = 'skipped' # primary meaning is that the check could not be performed due to a service outage or API error, but it's also overloaded to mean NOT_APPLICABLE so technically 'skipped' or 'error' could be applicable, but AWS seems to do the equivalent of skipped
          finding['message'] = detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") unless !detail['Compliance'].key?('StatusReasons')
        else
          finding['status'] = 'no_status'
          finding['message'] = detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") unless !detail['Compliance'].key?('StatusReasons')
        end
      else
        finding['status'] = 'no_status'
        finding['message'] = detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") unless !detail['Compliance'].key?('StatusReasons')
      end
      finding['code_desc'] = detail['Title']
      finding['start_time'] = detail.key?('LastObservedAt') ? detail['LastObservedAt'] : detail['UpdatedAt']
      [finding]
    end

    # todo: create aws submapper like prowler but this one gets the raw data from aws directly
    # todo: verify if prowler still works and add the id thing to each finding which is to extract [textNUMBER] from the title text
    # todo: finding id + resources->type and id as the subtest title thingy if they exists
    def to_hdf
      id_groups = {}
      @report['Findings'].each do |detail|
        printf("\rProcessing: %s", $spinner.next)

        item = {}
        item['id'] = if detail.member?('ProductFields') && detail['ProductFields'].member?('ControlId')
                       detail['ProductFields']['ControlId']
                     elsif detail.member?('ProductFields') && detail['ProductFields'].member?('RuleId')
                       detail['ProductFields']['RuleId']
                     elsif detail.member?('ProductFields') && detail['ProductFields'].member?('MITRESAFHDFId') # for our custom mappers
                       detail['ProductFields']['MITRESAFHDFId']
                     else
                       detail['Title'] # subfindings are grouped based on id so using the ideal case if it's there otherwise the guaranteed attribute
                     end
        item['title'] = "Finding id: #{detail['Id']}; Resources: [#{detail['Resources'].map { |r| "Type: #{r['Type']}, Id: #{r['Id']}" }.join(', ') }]"
        item['Title'] = detail['Title']

        item['tags'] = { nist: nist_tag(detail) }

        item['impact'] = impact(detail)

        item['desc'] = detail['Description']

        item['descriptions'] = []
        item['descriptions'] << desc_tags(detail['Remediation']['Recommendation'].map { |k,v| v }.join("\n"), 'fix') unless detail['Remediation'].nil? || detail['Remediation']['Recommendation'].nil?

        item['refs'] = []
        item['refs'] << { url: detail['SourceUrl'] } unless detail['SourceUrl'].nil?

        item['source_location'] = NA_HASH
        item['code'] = JSON.pretty_generate(detail)

        item['results'] = findings(detail)

        id_groups[item['id']] = [] if id_groups[item['id']].nil?
        id_groups[item['id']] << item
      end

      controls = []
      id_groups.each do |id, details|
        printf("\rProcessing: %s", $spinner.next)

        if details.one?
          controls << details[0] # not sure what to do to get the titles working properly cause there's no title attribute for a subfinding so these ones get the finding/resource thing and no actual title whereas the ones with multiple subfindings get a title but no finding/resources
        else
          item = {}
          item['id'] = id
          # require 'pry' # todo: remove
          # binding.pry
          item['title'] = details.map { |d| d['Title'] }.uniq.join("\n")

          item['tags'] = { nist: details.map { |d| d['tags'][:nist] }.flatten.uniq }

          item['impact'] = details.map { |d| d['impact'] }.max

          item['desc'] = details.map { |d| d['desc'] }.uniq.join("\n")

          item['descriptions'] = details.map { |d| d['descriptions'] }.flatten.compact.reject(&:empty?).uniq

          item['refs'] = details.map { |d| d['refs'] }.flatten.compact.reject(&:empty?).uniq

          item['source_location'] = NA_HASH
          item['code'] = "{ \"Findings\": [\n#{details.map { |d| d['code'] }.uniq.join(",\n")}\n]\n}" # todo: fix up the formatting some more - ex. findings key should be on new line

          item['results'] = details.map { |d| d['results'] }.flatten.uniq

          controls << item
        end
      end

      scaninfo = extract_scaninfo
      results = HeimdallDataFormat.new(profile_name: scaninfo['name'],
                                       title: scaninfo['title'],
                                       controls: controls)
      results.to_hdf
    end
  end
end
