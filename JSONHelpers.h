#ifndef _JSON_HELPERS_H_
#define _JSON_HELPERS_H_

#include "AnalyzeHelpers.h"

void to_json(nlohmann::json &j, const Parameter &p)
{
    j = nlohmann::json{{"Variable", p.Variable}, {"Type", p.Type}, {"Identifier", p.Identifier}, {"Fuzzable", p.Fuzzable}, {"CallValue", p.CallValue}};
}

void to_json(nlohmann::json &j, const Service &s)
{
    j = nlohmann::json{{"Service", s.Service}, {"ServiceType", s.ServiceType}, {"ServiceGUID", s.ServiceGUID}, {"ServiceDefName", s.ServiceDefName}, {"Parameters", s.Parameters}};
}

void to_json(nlohmann::json &j, const Analysis &a)
{
    j = nlohmann::json{{"ServiceInfo", a.ServiceInfo}, {"Includes", a.Includes}};
}

void generate_json(std::string filename, Analysis output_data)
{
    nlohmann::json all_results = output_data;
    std::ofstream all_file(filename);
    all_file << all_results.dump(4) << std::endl;
}

#endif