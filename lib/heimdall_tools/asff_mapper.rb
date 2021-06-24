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
    def initialize(asff_json)
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

    # potential todo: override with criticality if key exists?
    def impact(severity)
      IMPACT_MAPPING[severity.to_sym]
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
          finding['message'] = detail['Compliance'].key?('StatusReasons') ? detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") : detail['Title']
        when 'WARNING'
          finding['status'] = 'skipped'
          finding['skip_message'] = detail['Compliance'].key?('StatusReasons') ? detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") : detail['Title']
        when 'FAILED'
          finding['status'] = 'failed'
          finding['message'] = detail['Compliance'].key?('StatusReasons') ? detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") : detail['Title']
        when 'NOT_AVAILABLE'
          # require 'pry'
          # binding.pry
          finding['status'] = 'error' # todo: primary meaning is that the check could not be performed due to a service outage or API error, but it's also overloaded to mean NOT_APPLICABLE so 'error' might not be the correct status value at all times
          finding['message'] = detail['Compliance'].key?('StatusReasons') ? detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") : detail['Title']
        else
          finding['status'] = 'no_status'
          finding['message'] = detail['Compliance'].key?('StatusReasons') ? detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") : detail['Title']
        end
      else
        finding['status'] = 'no_status'
        finding['message'] = detail['Compliance'].key?('StatusReasons') ? detail['Compliance']['StatusReasons'].map { |reason| reason.flatten }.flatten.join("\n") : detail['Title']
      end
      finding['code_desc'] = detail['Title']
      finding['start_time'] = detail.key?('LastObservedAt') ? detail['LastObservedAt'] : detail['UpdatedAt']
      [finding]
    end

    def to_hdf
      controls = []
      @report['Findings'].each do |detail|
        printf("\rProcessing: %s", $spinner.next)

        item = {}
        item['id']                 = detail['Id']
        item['title']              = detail['Title']

        item['tags']               = { nist: nist_tag(detail) }

        item['impact']             = impact(detail['Severity'].key?('Label') ? detail['Severity']['Label'] : detail['Severity']['Normalized']) # severity is required, but can be either 'label' or 'normalized' internally with 'label' being preferred.  other values can be in here too such as the original severity rating.

        item['desc']               = detail['Description']

        item['descriptions']       = []
        item['descriptions']       << desc_tags(detail['Remediation']['Recommendation'].map { |k,v| v }.join("\n"), 'fix') unless detail['Remediation'].nil? || detail['Remediation']['Recommendation'].nil?

        item['refs']               = []
        item['refs']               << { url: detail['SourceUrl'] } unless detail['SourceUrl'].nil?

        item['source_location']    = NA_HASH
        item['code']               = JSON.pretty_generate(detail)

        item['results']            = findings(detail)

        controls << item
      end

      scaninfo = extract_scaninfo
      results = HeimdallDataFormat.new(profile_name: scaninfo['name'],
                                       title: scaninfo['title'],
                                       controls: controls)
      results.to_hdf
    end
  end
end
