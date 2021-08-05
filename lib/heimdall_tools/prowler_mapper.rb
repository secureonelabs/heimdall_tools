module HeimdallTools
  class ProwlerMapper < ASFFMapper
    def initialize(prowler_asff_json)
      # comes as an asff-json file which is basically all the findings concatenated into one file instead of putting it in the proper wrapper data structure
      super("{ \"Findings\": [#{prowler_asff_json.split("\n").join(',')}]}", meta: { 'name' => 'Prowler', 'title' => 'Prowler findings' })
    end
  end
end
