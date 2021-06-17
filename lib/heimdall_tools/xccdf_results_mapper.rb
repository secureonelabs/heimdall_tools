require 'json'
require 'csv'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'
require 'nokogiri'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

# XCCDF mapping for converting SCAP client (SCC or OpenSCAP) outputs to HDF
# SCC output from the RHEL7 Lockdown image was used for testing

U_CCI_LIST =   File.join(RESOURCE_DIR, 'U_CCI_List.xml')

IMPACT_MAPPING = {
  critical: 0.9,
  high: 0.7,
  medium: 0.5,
  low: 0.3,
  na: 0.0
}.freeze

# severity maps to high, medium, low with weights all being 10.0 from the xml
# it doesn't really look like SCAP or SCC cares about that value, just if its high, med, or low

CWE_REGEX = 'CWE-(\d*):'.freeze
CCI_REGEX = 'CCI-(\d*)'.freeze

DEFAULT_NIST_TAG = %w{SA-11 RA-5 Rev_4}.freeze

module HeimdallTools
  class XCCDFResultsMapper
    def initialize(scap_xml, _name = nil)
      @scap_xml = scap_xml
      read_cci_xml
      begin
        data = xml_to_hash(scap_xml)
        @results = data['Benchmark']['TestResult']
        @benchmarks = data['Benchmark']
        @groups = data['Benchmark']['Group']
      rescue StandardError => e
        raise "Invalid SCAP Client XCCDF output XML file provided Exception: #{e}"
      end
    end

    # change for pass/fail based on output Benchmark.rule
    # Pass/Fail are the only two options included in the output file
    def finding(issue, count)
      finding = {}
      finding['status'] = issue['rule-result'][count]['result'].to_s
      if finding['status'] == 'pass'
        finding['status'] = 'passed'
      end
      if finding['status'] == 'fail'
        finding['status'] = 'failed'
      end
      finding['code_desc']      = NA_STRING
      finding['run_time']       = NA_FLOAT
      finding['start_time']     = issue['start-time']
      finding['message']        = NA_STRING
      finding['resource_class'] = NA_STRING
      [finding]
    end

    def read_cci_xml
      @cci_xml = Nokogiri::XML(File.open(U_CCI_LIST))
      @cci_xml.remove_namespaces!
    rescue StandardError => e
      puts "Exception: #{e.message}"
    end

    def cci_nist_tag(cci_refs)
      nist_tags = []
      cci_refs.each do |cci_ref|
        item_node = @cci_xml.xpath("//cci_list/cci_items/cci_item[@id='#{cci_ref}']")[0] unless @cci_xml.nil?
        unless item_node.nil?
          nist_ref = item_node.xpath('./references/reference[not(@version <= preceding-sibling::reference/@version) and not(@version <=following-sibling::reference/@version)]/@index').text
        end
        nist_tags << nist_ref
      end
      nist_tags
    end

    def get_impact(severity)
      IMPACT_MAPPING[severity.to_sym]
    end

    def parse_refs(refs)
      refs.map { |ref| ref['text'] if ref['text'].match?(CCI_REGEX) }.reject!(&:nil?)
    end

    # Clean up output by removing the Satsifies block and the end of the description
    def satisfies_parse(satisf)
      temp_satisf = satisf.match('Satisfies: ([^;]*)<\/VulnDiscussion>')
      return temp_satisf[1].split(',') unless temp_satisf.nil?

      NA_ARRAY
    end

    def desc_tags(data, label)
      { data: data || NA_STRING, label: label || NA_STRING }
    end

    def collapse_duplicates(controls)
      unique_controls = []

      controls.map { |x| x['id'] }.uniq.each do |id|
        collapsed_results = controls.select { |x| x['id'].eql?(id) }.map { |x| x['results'] }
        unique_control = controls.find { |x| x['id'].eql?(id) }
        unique_control['results'] = collapsed_results.flatten
        unique_controls << unique_control
      end
      unique_controls
    end

    def to_hdf
      controls = []
      @groups.each_with_index do |group, i|
        @item = {}
        @item['id'] = group['Rule']['id'].split('.').last.split('_').drop(2).first.split('r').first.split('S')[1]
        @item['title']               = group['Rule']['title'].to_s
        @item['desc']                = group['Rule']['description'].to_s.split('Satisfies').first
        @item['descriptions']		 = []
        @item['descriptions']		 << desc_tags(group['Rule']['description'], 'default')
        @item['descriptions']		 << desc_tags('NA', 'rationale')
        @item['descriptions']		 << desc_tags(group['Rule']['check']['check-content-ref']['name'], 'check')
        @item['descriptions']		 << desc_tags(group['Rule']['fixtext']['text'], 'fix')
        @item['impact']				 = get_impact(group['Rule']['severity'])
        @item['refs']				 = NA_ARRAY
        @item['tags']				 = {}
        @item['tags']['severity']    = nil
        @item['tags']['gtitle']      = group['title']
        @item['tags']['satisfies']   = satisfies_parse(group['Rule']['description'])
        @item['tags']['gid']         = group['Rule']['id'].split('.').last.split('_').drop(2).first.split('r').first
        @item['tags']['legacy_id']   = group['Rule']['ident'][2]['text']
        @item['tags']['rid']         = group['Rule']['ident'][1]['text']
        @item['tags']['stig_id']     = @benchmarks['id']
        @item['tags']['fix_id']      = group['Rule']['fix']['id']
        @item['tags']['cci']         = parse_refs(group['Rule']['ident'])
        @item['tags']['nist']        = cci_nist_tag(@item['tags']['cci'])
        @item['code']                = NA_STRING
        @item['source_location'] = NA_HASH
        # results were in another location and using the top block "Benchmark" as a starting point caused odd issues. This works for now for the results.
        @item['results'] = finding(@results, i)
        controls << @item
      end

      controls = collapse_duplicates(controls)
      results = HeimdallDataFormat.new(profile_name: @benchmarks['id'],
                                       version: @benchmarks['style'],
                                       duration: NA_FLOAT,
                                       title: @benchmarks['title'],
                                       maintainer: @benchmarks['reference']['publisher'],
                                       summary: @benchmarks['description'],
                                       license: @benchmarks['notice']['id'],
                                       copyright: @benchmarks['metadata']['creator'],
                                       copyright_email: 'disa.stig_spt@mail.mil',
                                       controls: controls)
      results.to_hdf
    end
  end
end
