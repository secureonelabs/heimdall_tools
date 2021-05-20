require 'json'
require 'csv'
require 'heimdall_tools/hdf'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

SCOUTSUITE_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'scoutsuite-nist-mapping.csv')

IMPACT_MAPPING = {
  danger: 0.7,
  warning: 0.5
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
  # currently only tested against an AWS based result, but ScoutSuite supports many other cloud providers such as Azure
  class ScoutSuiteMapper
    def initialize(scoutsuite_js)
      begin
        @scoutsuite_nist_mapping = parse_mapper
      rescue StandardError => e
        raise "Invalid Scout Suite to NIST mapping file:\nException: #{e}"
      end

      begin
        @scoutsuite_json = scoutsuite_js.lines[1] # first line is `scoutsuite_results =\n` and second line is json
        @report = JSON.parse(@scoutsuite_json)
      rescue StandardError => e
        raise "Invalid Scout Suite JavaScript file provided:\nException: #{e}"
      end
    end

    def parse_mapper
      csv_data = CSV.read(SCOUTSUITE_NIST_MAPPING_FILE, { encoding: 'UTF-8', headers: true, header_converters: :symbol })
      csv_data.map(&:to_hash)
    end

    def create_attribute(name, value, required = nil, sensitive = nil, type = nil)
      { name: name, options: { value: value, required: required, sensitive: sensitive, type: type }.compact }
    end

    def extract_scaninfo(report)
      info = {}
      begin
        info['name'] = 'Scout Suite Multi-Cloud Security Auditing Tool'
        info['version'] = report['last_run']['version']
        info['title'] = "Scout Suite Report using #{report['last_run']['ruleset_name']} ruleset on #{report['provider_name']} with account #{report['account_id']}"
        info['target_id'] = "#{report['last_run']['ruleset_name']} ruleset:#{report['provider_name']}:#{report['account_id']}"
        info['summary'] = report['last_run']['ruleset_about']
        info['attributes'] = [
          create_attribute('account_id', report['account_id'], true, false, INSPEC_INPUTS_MAPPING[:string]),
          create_attribute('environment', report['environment']),
          create_attribute('ruleset', report['ruleset_name']),
          # think at least these run_parameters are aws only
          create_attribute('run_parameters_excluded_regions', report['last_run']['run_parameters']['excluded_regions'].join(', ')),
          create_attribute('run_parameters_regions', report['last_run']['run_parameters']['regions'].join(', ')),
          create_attribute('run_parameters_services', report['last_run']['run_parameters']['services'].join(', ')),
          create_attribute('run_parameters_skipped_services', report['last_run']['run_parameters']['skipped_services'].join(', ')),
          create_attribute('time', report['last_run']['time']),
          create_attribute('partition', report['partition']), # think this is aws only
          create_attribute('provider_code', report['provider_code']),
          create_attribute('provider_name', report['provider_name']),
        ]

        info
      rescue StandardError => e
        raise "Error extracting report info from Scout Suite JS->JSON file:\nException: #{e}"
      end
    end

    def nist_tag(rule)
      entries = @scoutsuite_nist_mapping.select { |x| rule.eql?(x[:rule].to_s) && !x[:nistid].nil? }
      tags = entries.map { |x| x[:nistid].split('|') }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def impact(severity)
      IMPACT_MAPPING[severity.to_sym]
    end

    def desc_tags(data, label)
      { data: data || NA_STRING, label: label || NA_STRING }
    end

    def findings(details)
      finding = {}
      if (details['checked_items']).zero?
        finding['status'] = 'skipped'
        finding['skip_message'] = 'Skipped because no items were checked'
      elsif (details['flagged_items']).zero?
        finding['status'] = 'passed'
        finding['message'] = "0 flagged items out of #{details['checked_items']} checked items"
      else # there are checked items and things were flagged
        finding['status'] = 'failed'
        finding['message'] = "#{details['flagged_items']} flagged items out of #{details['checked_items']} checked items:\n#{details['items'].join("\n")}"
      end
      finding['code_desc'] = details['description']
      finding['start_time'] = @report['last_run']['time']
      [finding]
    end

    def compliance(arr)
      str = 'Compliant with '
      arr.map do |val|
        info = "#{val['name']}, reference #{val['reference']}, version #{val['version']}"
        str + info
      end.join("\n")
    end

    def to_hdf
      controls = []
      @report['services'].each_key do |service|
        @report['services'][service]['findings'].each_key do |finding|
          printf("\rProcessing: %s", $spinner.next)

          finding_id = finding
          finding_details = @report['services'][service]['findings'][finding]

          item = {}
          item['id']                 = finding_id
          item['title']              = finding_details['description']

          item['tags']               = { nist: nist_tag(finding_id) }

          item['impact']             = impact(finding_details['level'])

          item['desc']               = finding_details['rationale']

          item['descriptions']       = []
          item['descriptions']       << desc_tags(finding_details['remediation'], 'fix') unless finding_details['remediation'].nil?
          item['descriptions']       << desc_tags(finding_details['service'], 'service')
          item['descriptions']       << desc_tags(finding_details['path'], 'path')
          item['descriptions']       << desc_tags(finding_details['id_suffix'], 'id_suffix')

          item['refs']               = []
          item['refs']               += finding_details['references'].map { |link| { url: link } } unless finding_details['references'].nil? || finding_details['references'].empty?
          item['refs']               << { ref: compliance(finding_details['compliance']) } unless finding_details['compliance'].nil?

          item['source_location']    = NA_HASH
          item['code']               = NA_STRING

          item['results']            = findings(finding_details)

          controls << item
        end
      end

      scaninfo = extract_scaninfo(@report)
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
