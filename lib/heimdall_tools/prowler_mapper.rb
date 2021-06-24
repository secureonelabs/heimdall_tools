module HeimdallTools
  class ProwlerMapper < ASFFMapper
    def initialize(prowler_asff_json)
      super("{ \"Findings\": [#{prowler_asff_json.split("\n").join(',')}]}")
    end
  end
end
