require 'json'
require 'csv'
require 'heimdall_tools/hdf'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

# todo: remove all this nist mapping stuff or figure out alternative
SCOUTSUITE_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'scoutsuite-nist-mapping.csv')

# todo: confirm if these seem like reasonable mappings
IMPACT_MAPPING = {
  CRITICAL: 1.0,
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
        @scoutsuite_nist_mapping = parse_mapper
      rescue StandardError => e
        raise "Invalid Scout Suite to NIST mapping file:\nException: #{e}"
      end

      begin
        # TODO: support findings wrapper attribute - currently only expects a json object with just one control in it
        @report = JSON.parse(asff_json)
      rescue StandardError => e
        raise "Invalid ASFF file provided:\nException: #{e}"
      end
    end

    def parse_mapper
      csv_data = CSV.read(SCOUTSUITE_NIST_MAPPING_FILE, { encoding: 'UTF-8', headers: true, header_converters: :symbol })
      csv_data.map(&:to_hash)
    end

    def create_attribute(name, value, required = nil, sensitive = nil, type = nil)
      { name: name, options: { value: value, required: required, sensitive: sensitive, type: type }.compact }
    end

    def extract_scaninfo
      info = {}
      begin
        info['name'] = 'AWS Security Finding Format'
        info['version'] = @report['SchemaVersion']
        info['title'] = "ASFF finding (#{@report['Id']}) on account #{@report['AwsAccountId']}"
        info['target_id'] = "Id: #{@report['Id']} Account: #{@report['AwsAccountId']} Product: #{@report['ProductArn']} Generator: #{@report['GeneratorId']}"
        info['summary'] = @report['Types'].join(',')
        info['attributes'] = @report.map { |k,v| create_attribute(k, v) } # potential todo: contains duplicate info, so can do like a filter against items like schemaversion that already have a dedicated spot
        info
      rescue StandardError => e
        raise "Error extracting report info from ASFF file:\nException: #{e}"
      end
    end

    # todo: can't figure out mappings even after looking at aws_config mappings
    def nist_tag
      # entries = @scoutsuite_nist_mapping.select { |x| rule.eql?(x[:rule].to_s) && !x[:nistid].nil? }
      # tags = entries.map { |x| x[:nistid].split('|') }
      # tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
      DEFAULT_NIST_TAG
    end

    # potential todo: override with criticality if key exists?  what about confidence?  what about verificationstate?
    def impact(severity)
      IMPACT_MAPPING[severity.to_sym]
    end

    def desc_tags(data, label)
      { data: data || NA_STRING, label: label || NA_STRING }
    end

    # potential todo: recordstate - is it passing or skipped if the recordstate is archived (other option is active which is obv gonna be failed).  what about compliance?
    def findings
      finding = {}
      if (@report['Severity'].key?('Label') ? @report['Severity']['Label'] : @report['Severity']['Normalized']).eql? 'INFORMATIONAL'
        finding['status'] = 'skipped'
        finding['skip_message'] = 'Skipped because it is only informational'
      else
        finding['status'] = 'failed'
        finding['message'] = "Product #{@report['ProductArn']} created finding #{@report['Id']} based off of generator #{@report['GeneratorId']} for account #{@report['Id']}"
      end
      finding['code_desc'] = @report['Title']
      finding['start_time'] = @report.key?('LastObservedAt') ? @report['LastObservedAt'] : @report['UpdatedAt']
      [finding]
    end

    def to_hdf
      controls = []
      printf("\rProcessing: %s", $spinner.next)

      item = {}
      item['id']                 = @report['Id']
      item['title']              = @report['Title']

      item['tags']               = { nist: nist_tag }

      item['impact']             = impact(@report['Severity'].key?('Label') ? @report['Severity']['Label'] : @report['Severity']['Normalized']) # severity is required, but can be either 'label' or 'normalized' internally with 'label' being preferred.  other values can be in here too such as the original severity rating.

      item['desc']               = @report['Description']

      item['descriptions']       = []
      item['descriptions']       << desc_tags(@report['Remediation']['Recommendation'].map { |k,v| v }.join("\n"), 'fix') unless @report['Remediation'].nil? || @report['Remediation']['Recommendation'].nil?

      item['refs']               = []
      item['refs']               << @report['SourceUrl'] unless @report['SourceUrl'].nil?

      item['source_location']    = NA_HASH
      item['code']               = NA_STRING

      item['results']            = findings

      controls << item

      scaninfo = extract_scaninfo
      results = HeimdallDataFormat.new(profile_name: scaninfo['name'],
                                       version: scaninfo['version'],
                                       title: scaninfo['title'],
                                       summary: scaninfo['summary'],
                                       controls: controls,
                                       target_id: scaninfo['target_id'],
                                       attributes: scaninfo['attributes'])
      results.to_hdf
    end
  end
end
