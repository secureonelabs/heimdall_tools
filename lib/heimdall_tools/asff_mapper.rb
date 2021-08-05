require 'json'
require 'htmlentities'

require 'heimdall_tools/hdf'
require 'heimdall_tools/asff_compatible_products/firewall_manager'
require 'heimdall_tools/asff_compatible_products/prowler'
require 'heimdall_tools/asff_compatible_products/securityhub'

module HeimdallTools
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

  class ASFFMapper
    IMPACT_MAPPING = {
      CRITICAL: 0.9,
      HIGH: 0.7,
      MEDIUM: 0.5,
      LOW: 0.3,
      INFORMATIONAL: 0.0
    }.freeze

    PRODUCT_ARN_MAPPING = {
      %r{arn:.+:securityhub:.+:.*:product/aws/firewall-manager} => FirewallManager,
      %r{arn:.+:securityhub:.+:.*:product/aws/securityhub} => SecurityHub,
      %r{arn:.+:securityhub:.+:.*:product/prowler/prowler} => Prowler
    }.freeze

    def initialize(asff_json, securityhub_standards_json_array: nil, meta: nil)
      @meta = meta

      @supporting_docs = {}
      @supporting_docs[SecurityHub] = SecurityHub.supporting_docs({ standards: securityhub_standards_json_array })

      begin
        asff_required_keys = %w{AwsAccountId CreatedAt Description GeneratorId Id ProductArn Resources SchemaVersion Severity Title Types UpdatedAt}
        @report = JSON.parse(asff_json)
        if @report.length == 1 && @report.member?('Findings') && @report['Findings'].each { |finding| asff_required_keys.difference(finding.keys).none? }.all?
          # ideal case that is spec compliant
          # might need to ensure that the file is utf-8 encoded and remove a BOM if one exists
        elsif asff_required_keys.difference(@report.keys).none?
          # individual finding so have to add wrapping array
          @report = { 'Findings' => [@report] }
        else
          raise 'Not a findings file nor an individual finding'
        end
      rescue StandardError => e
        raise "Invalid ASFF file provided:\nException: #{e}"
      end

      @coder = HTMLEntities.new
    end

    def encode(string)
      @coder.encode(string, :basic, :named, :decimal)
    end

    def external_product_handler(product, data, func, default)
      if (product.is_a?(Regexp) || (arn = PRODUCT_ARN_MAPPING.keys.find { |a| product.match(a) })) && PRODUCT_ARN_MAPPING.key?(arn || product) && PRODUCT_ARN_MAPPING[arn || product].respond_to?(func)
        keywords = { encode: method(:encode) }
        keywords = keywords.merge(@supporting_docs[PRODUCT_ARN_MAPPING[arn || product]]) if @supporting_docs.member?(PRODUCT_ARN_MAPPING[arn || product])
        PRODUCT_ARN_MAPPING[arn || product].send(func, data, **keywords)
      elsif default.is_a? Proc
        default.call
      else
        default
      end
    end

    def nist_tag(finding)
      entries = external_product_handler(finding['ProductArn'], finding, :finding_nist_tag, {})
      tags = entries.map { |rule| rule[:nistid].split('|') }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def impact(finding)
      # there can be findings listed that are intentionally ignored due to the underlying control being superceded by a control from a different standard
      if finding.member?('Workflow') && finding['Workflow'].member?('Status') && finding['Workflow']['Status'] == 'SUPPRESSED'
        imp = :INFORMATIONAL
      else
        # severity is required, but can be either 'label' or 'normalized' internally with 'label' being preferred.  other values can be in here too such as the original severity rating.
        default = proc { finding['Severity'].key?('Label') ? finding['Severity']['Label'].to_sym : finding['Severity']['Normalized']/100.0 }
        imp = external_product_handler(finding['ProductArn'], finding, :finding_impact, default)
      end
      imp.is_a?(Symbol) ? IMPACT_MAPPING[imp] : imp
    end

    def desc_tags(data, label)
      { data: data || NA_STRING, label: label || NA_STRING }
    end

    def subfindings(finding)
      subfinding = {}

      statusreason = finding['Compliance']['StatusReasons'].map { |reason| reason.flatten.map { |string| encode(string) } }.flatten.join("\n") if finding.key?('Compliance') && finding['Compliance'].key?('StatusReasons')
      if finding.key?('Compliance') && finding['Compliance'].key?('Status')
        case finding['Compliance']['Status']
        when 'PASSED'
          subfinding['status'] = 'passed'
          subfinding['message'] = statusreason if statusreason
        when 'WARNING'
          subfinding['status'] = 'skipped'
          subfinding['skip_message'] = statusreason if statusreason
        when 'FAILED'
          subfinding['status'] = 'failed'
          subfinding['message'] = statusreason if statusreason
        when 'NOT_AVAILABLE'
          # primary meaning is that the check could not be performed due to a service outage or API error, but it's also overloaded to mean NOT_APPLICABLE so technically 'skipped' or 'error' could be applicable, but AWS seems to do the equivalent of skipped
          subfinding['status'] = 'skipped'
          subfinding['message'] = statusreason if statusreason
        else
          subfinding['status'] = 'no_status'
          subfinding['message'] = statusreason if statusreason
        end
      else
        subfinding['status'] = 'no_status'
        subfinding['message'] = statusreason if statusreason
      end

      subfinding['code_desc'] = external_product_handler(finding['ProductArn'], finding, :subfindings_code_desc, '')
      subfinding['code_desc'] += '; ' unless subfinding['code_desc'].empty?
      subfinding['code_desc'] += "Resources: [#{finding['Resources'].map { |r| "Type: #{encode(r['Type'])}, Id: #{encode(r['Id'])}#{", Partition: #{encode(r['Partition'])}" if r.key?('Partition')}#{", Region: #{encode(r['Region'])}" if r.key?('Region')}" }.join(', ')}]"

      subfinding['start_time'] = finding.key?('LastObservedAt') ? finding['LastObservedAt'] : finding['UpdatedAt']

      [subfinding]
    end

    def to_hdf
      product_groups = {}
      @report['Findings'].each do |finding|
        printf("\rProcessing: %s", $spinner.next)

        external = method(:external_product_handler).curry(4)[finding['ProductArn']][finding]

        # group subfindings by asff productarn and then hdf id
        item = {}
        item['id'] = external[:finding_id][encode(finding['GeneratorId'])]

        item['title'] = external[:finding_title][encode(finding['Title'])]

        item['tags'] = { nist: nist_tag(finding) }

        item['impact'] = impact(finding)

        item['desc'] = encode(finding['Description'])

        item['descriptions'] = []
        item['descriptions'] << desc_tags(finding['Remediation']['Recommendation'].map { |_k, v| encode(v) }.join("\n"), 'fix') if finding.key?('Remediation') && finding['Remediation'].key?('Recommendation')

        item['refs'] = []
        item['refs'] << { url: finding['SourceUrl'] } if finding.key?('SourceUrl')

        item['source_location'] = NA_HASH

        item['results'] = subfindings(finding)

        arn = PRODUCT_ARN_MAPPING.keys.find { |a| finding['ProductArn'].match(a) }
        if arn.nil?
          product_info = finding['ProductArn'].split(':')[-1]
          arn = Regexp.new "arn:.+:securityhub:.+:.*:product/#{product_info.split('/')[1]}/#{product_info.split('/')[2]}"
        end
        product_groups[arn] = {} if product_groups[arn].nil?
        product_groups[arn][item['id']] = [] if product_groups[arn][item['id']].nil?
        product_groups[arn][item['id']] << [item, finding]
      end

      controls = []
      product_groups.each do |product, id_groups|
        id_groups.each do |id, data|
          printf("\rProcessing: %s", $spinner.next)

          external = method(:external_product_handler).curry(4)[product]

          group = data.map { |d| d[0] }
          findings = data.map { |d| d[1] }

          product_info = findings[0]['ProductArn'].split(':')[-1].split('/')
          product_name = external[findings][:product_name][encode("#{product_info[1]}/#{product_info[2]}")]

          item = {}
          # add product name to id if any ids are the same across products
          item['id'] = product_groups.filter { |pg| pg != product }.values.any? { |ig| ig.keys.include?(id) } ? "[#{product_name}] #{id}" : id

          item['title'] = "#{product_name}: #{group.map { |d| d['title'] }.uniq.join(';')}"

          item['tags'] = { nist: group.map { |d| d['tags'][:nist] }.flatten.uniq }

          item['impact'] = group.map { |d| d['impact'] }.max

          item['desc'] = external[group][:desc][group.map { |d| d['desc'] }.uniq.join("\n")]

          item['descriptions'] = group.map { |d| d['descriptions'] }.flatten.compact.reject(&:empty?).uniq

          item['refs'] = group.map { |d| d['refs'] }.flatten.compact.reject(&:empty?).uniq

          item['source_location'] = NA_HASH
          item['code'] = JSON.pretty_generate({ Findings: findings })

          item['results'] = group.map { |d| d['results'] }.flatten.uniq

          controls << item
        end
      end

      results = HeimdallDataFormat.new(profile_name: @meta&.key?('name') ? @meta['name'] : 'AWS Security Finding Format',
                                       title: @meta&.key?('title') ? @meta['title'] : 'ASFF findings',
                                       controls: controls)
      results.to_hdf
    end
  end
end
