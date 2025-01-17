# require_relative '../utilities/' Place any utility code in utilities folder and require here

module HeimdallTools
  class CLI < Command
    desc 'fortify_mapper', 'fortify_mapper translates Fortify fvdl files to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:fortify_mapper)
    option :fvdl, required: true, aliases: '-f'
    option :output, required: true, aliases: '-o'
    def fortify_mapper
      hdf = HeimdallTools::FortifyMapper.new(File.read(options[:fvdl])).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'zap_mapper', 'zap_mapper translates OWASP ZAP results Json to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:fortify_mapper)
    option :json, required: true, aliases: '-j'
    option :name, required: true, aliases: '-n'
    option :output, required: true, aliases: '-o'
    def zap_mapper
      hdf = HeimdallTools::ZapMapper.new(File.read(options[:json]), options[:name]).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'sonarqube_mapper', 'sonarqube_mapper pulls SonarQube results, for the specified project name, from the API and outputs in HDF format Json to be viewed on Heimdall'
    long_desc Help.text(:sonarqube_mapper)
    option :name, required: true, aliases: '-n'
    option :api_url, required: true, aliases: '-u'
    option :auth, type: :string, required: false
    option :output, required: true, aliases: '-o'
    def sonarqube_mapper
      hdf = HeimdallTools::SonarQubeMapper.new(options[:name], options[:api_url], options[:auth]).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'burpsuite_mapper', 'burpsuite_mapper translates Burpsuite xml report to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:burpsuite_mapper)
    option :xml, required: true, aliases: '-x'
    option :output, required: true, aliases: '-o'
    def burpsuite_mapper
      hdf = HeimdallTools::BurpSuiteMapper.new(File.read(options[:xml])).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'xccdf_results_mapper', 'xccdf_results_mapper translates SCAP client XCCDF-Results XML report to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:xccdf_results_mapper)
    option :xml, required: true, aliases: '-x'
    option :output, required: true, aliases: '-o'
    def xccdf_results_mapper
      hdf = HeimdallTools::XCCDFResultsMapper.new(File.read(options[:xml])).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'nessus_mapper', 'nessus_mapper translates nessus xml report to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:nessus_mapper)
    option :xml, required: true, aliases: '-x'
    option :output_prefix, required: true, aliases: '-o'
    def nessus_mapper
      hdfs = HeimdallTools::NessusMapper.new(File.read(options[:xml])).to_hdf

      puts "\nHDF Generated:"
      hdfs.each_key do |host|
        File.write("#{options[:output_prefix]}-#{host}.json", hdfs[host])
        puts "#{options[:output_prefix]}-#{host}.json"
      end
    end

    desc 'snyk_mapper', 'snyk_mapper translates Snyk results Json to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:snyk_mapper)
    option :json, required: true, aliases: '-j'
    option :output_prefix, required: true, aliases: '-o'
    def snyk_mapper
      hdfs = HeimdallTools::SnykMapper.new(File.read(options[:json]), options[:name]).to_hdf
      puts "\rHDF Generated:\n"
      hdfs.each_key do |host|
        File.write("#{options[:output_prefix]}-#{host}.json", hdfs[host])
        puts "#{options[:output_prefix]}-#{host}.json"
      end
    end

    desc 'nikto_mapper', 'nikto_mapper translates Nikto results Json to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:nikto_mapper)
    option :json, required: true, aliases: '-j'
    option :output, required: true, aliases: '-o'
    def nikto_mapper
      hdf = HeimdallTools::NiktoMapper.new(File.read(options[:json])).to_hdf
      File.write(options[:output], hdf)
      puts "\rHDF Generated:\n"
      puts options[:output].to_s
    end

    desc 'jfrog_xray_mapper', 'jfrog_xray_mapper translates Jfrog Xray results Json to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:jfrog_xray_mapper)
    option :json, required: true, aliases: '-j'
    option :output, required: true, aliases: '-o'
    def jfrog_xray_mapper
      hdf = HeimdallTools::JfrogXrayMapper.new(File.read(options[:json])).to_hdf
      File.write(options[:output], hdf)
      puts "\rHDF Generated:\n"
      puts options[:output].to_s
    end

    desc 'dbprotect_mapper', 'dbprotect_mapper translates dbprotect results xml to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:dbprotect_mapper)
    option :xml, required: true, aliases: '-x'
    option :output, required: true, aliases: '-o'
    def dbprotect_mapper
      hdf = HeimdallTools::DBProtectMapper.new(File.read(options[:xml])).to_hdf
      File.write(options[:output], hdf)
      puts "\rHDF Generated:\n"
      puts options[:output].to_s
    end

    desc 'aws_config_mapper', 'aws_config_mapper pulls Ruby AWS SDK data to translate AWS Config Rule results into HDF format Json to be viewable in Heimdall'
    long_desc Help.text(:aws_config_mapper)
    # option :custom_mapping, required: false, aliases: '-m'
    option :output, required: true, aliases: '-o'
    def aws_config_mapper
      hdf = HeimdallTools::AwsConfigMapper.new(options[:custom_mapping]).to_hdf
      File.write(options[:output], hdf)
      puts "\rHDF Generated:\n"
      puts options[:output].to_s
    end

    desc 'netsparker_mapper', 'netsparker_mapper translates netsparker enterprise results xml to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:netsparker_mapper)
    option :xml, required: true, aliases: '-x'
    option :output, required: true, aliases: '-o'
    def netsparker_mapper
      hdf = HeimdallTools::NetsparkerMapper.new(File.read(options[:xml])).to_hdf
      File.write(options[:output], hdf)
      puts "\rHDF Generated:\n"
      puts options[:output].to_s
    end

    desc 'sarif_mapper', 'sarif_mapper translates a SARIF JSON file into HDF format JSON to be viewable in Heimdall'
    long_desc Help.text(:sarif_mapper)
    option :json, required: true, aliases: '-j'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def sarif_mapper
      hdf = HeimdallTools::SarifMapper.new(File.read(options[:json])).to_hdf
      File.write(options[:output], hdf)
      puts "\rHDF Generated:\n"
      puts options[:output].to_s
    end

    desc 'scoutsuite_mapper', 'scoutsuite_mapper translates Scout Suite results from Javascript to HDF-formatted JSON so as to be viewable on Heimdall'
    long_desc Help.text(:scoutsuite_mapper)
    option :javascript, required: true, banner: 'SCOUTSUITE-RESULTS-JS', aliases: ['-i', '--input', '-j']
    option :output, required: true, banner: 'HDF-SCAN-RESULTS-JSON', aliases: '-o'
    def scoutsuite_mapper
      hdf = HeimdallTools::ScoutSuiteMapper.new(File.read(options[:javascript])).to_hdf
      File.write(options[:output], hdf)
      puts "\rHDF Generated:\n"
      puts options[:output].to_s
    end

    desc 'asff_mapper', 'asff_mapper translates AWS Security Finding Format results from JSON to HDF-formatted JSON so as to be viewable on Heimdall'
    long_desc Help.text(:asff_mapper)
    option :json, required: true, banner: 'ASFF-FINDING-JSON', aliases: ['-i', '--input', '-j']
    option :securityhub_standards, required: false, type: :array, banner: 'ASFF-SECURITYHUB-STANDARDS-JSON', aliases: ['--sh', '--input-securityhub-standards']
    option :output, required: true, banner: 'HDF-SCAN-RESULTS-JSON', aliases: '-o'
    def asff_mapper
      hdf = HeimdallTools::ASFFMapper.new(File.read(options[:json]), securityhub_standards_json_array: options[:securityhub_standards].nil? ? nil : options[:securityhub_standards].map { |filename| File.read(filename) }).to_hdf
      File.write(options[:output], hdf)
      puts "\rHDF Generated:\n"
      puts options[:output].to_s
    end

    desc 'prowler_mapper', 'prowler_mapper translates Prowler-derived AWS Security Finding Format results from concatenated JSON blobs to HDF-formatted JSON so as to be viewable on Heimdall'
    long_desc Help.text(:prowler_mapper)
    option :json, required: true, banner: 'PROWLER-ASFF-JSON', aliases: ['-i', '--input', '-j']
    option :output, required: true, banner: 'HDF-SCAN-RESULTS-JSON', aliases: '-o'
    def prowler_mapper
      hdf = HeimdallTools::ProwlerMapper.new(File.read(options[:json])).to_hdf
      File.write(options[:output], hdf)
      puts "\rHDF Generated:\n"
      puts options[:output].to_s
    end

    desc 'version', 'prints version'
    def version
      puts VERSION
    end
  end
end
