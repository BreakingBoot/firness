#ifndef __FILE_OP_HELPERS_H__
#define __FILE_OP_HELPERS_H__

#include "Globals.h"
#include <nlohmann/json.hpp>


namespace FileOps {
    /*
        Responsible for outputting the include statements collected accross all files analyzed
    */
    void outputIncludes(const std::string &filename, const std::set<std::string>& includes)
    {
        std::string file_path = filename + "/includes.json";
        nlohmann::json j = nlohmann::json::array();

        for (const auto& str : includes) {
            j.push_back(str);
        }

        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }
    /*
        Responsible for writing the structure type information
        gathered from the analysis to a json output file called types

    */
    void outputTypeStructs(const std::string &filename, const std::map<std::string, TypeData>& final) {
        std::string file_path = filename + "/types.json";
        nlohmann::json j;

        for (const auto& pair : final) {
            const TypeData& typeData = pair.second;
            nlohmann::json typeJson;
            typeJson["TypeName"] = typeData.TypeName;

            nlohmann::json fieldsJson;
            for (const FieldInfo& fieldInfo : typeData.Fields) {
                nlohmann::json fieldJson;
                fieldJson["Name"] = fieldInfo.Name;
                fieldJson["Type"] = fieldInfo.Type;
                fieldsJson.push_back(fieldJson);
            }
            typeJson["Fields"] = fieldsJson;

            j.push_back(typeJson);
        }

        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    /*
        Prints all of the call site information obtained from the
        pass to a json file call call-database
        "Arguments": {
            "Arg_0": {
                "arg_dir": "",
                "arg_type": "",
                "assignment": "",
                "data_type": "",
                "usage": "",
                "variable": ""
            },
            "Arg_1": {
                "arg_dir": "",
                "arg_type": "",
                "assignment": "",
                "data_type": "",
                "usage": "",
                "variable": ""
            },
            "Arg_2": {
                "arg_dir": "IN/OUT/IN_OUT",
                "arg_type": "",
                "assignment": "", -> Last assignment that happened
                "data_type": "",
                "usage": "", -> source code of call arg
                "variable": ""
            }
        },
        "Function": "FuncName"

        data_type and arg_type are both included incase a cast to VOID happens
        other than the built in variables I also included 3 more types for
        the cases of constants being directly used:
            - __CONSTANT_SIZEOF__
            - __CONSTANT_INT__
            - __CONSTANT_STRING__
    */
    void outputCallMap(const std::string& filename, std::vector<Call> callMap) {
        std::string file_path = filename + "/call-database.json";
        nlohmann::json jsonOutput;

        // Iterate over the CallMap
        for (const auto& call : callMap) {
            // Create a JSON object for each call
            nlohmann::json callObject;
            callObject["Function"] = call.Function;
            callObject["Service"] = call.Service;
            callObject["Include"] = call.includes;

            for (const auto& argumentPair : call.Arguments) {
                // Create a JSON object for each argument
                nlohmann::json argObject;
                const Argument& arg = argumentPair.second;
                argObject["data_type"] = arg.data_type;
                argObject["variable"] = arg.variable;
                argObject["assignment"] = arg.assignment;
                argObject["arg_dir"] = arg.arg_dir;
                argObject["arg_type"] = arg.arg_type;
                argObject["usage"] = arg.usage;

                callObject["Arguments"][argumentPair.first] = argObject;
            }

            // Add the call object to the JSON output
            jsonOutput.push_back(callObject);
        }

        // Write the JSON object to a file
        std::ofstream outFile(file_path);
        outFile << jsonOutput.dump(4);
        outFile.close();
    }

    /*
        Prints all of the call site information obtained from the
        pass to a json file call call-database
        "Arguments": {
            "Arg_0": {
                "arg_dir": "",
                "arg_type": "",
                "assignment": "",
                "data_type": "",
                "usage": "",
                "variable": ""
            },
            "Arg_1": {
                "arg_dir": "",
                "arg_type": "",
                "assignment": "",
                "data_type": "",
                "usage": "",
                "variable": ""
            },
            "Arg_2": {
                "arg_dir": "IN/OUT/IN_OUT",
                "arg_type": "",
                "assignment": "", -> Last assignment that happened
                "data_type": "",
                "usage": "", -> source code of call arg
                "variable": ""
            }
        },
        "Function": "FuncName"

        data_type and arg_type are both included incase a cast to VOID happens
        other than the built in variables I also included 3 more types for
        the cases of constants being directly used:
            - __CONSTANT_SIZEOF__
            - __CONSTANT_INT__
            - __CONSTANT_STRING__
    */
    void outputGeneratorMap(const std::string& filename, std::vector<Call> GenMap) {
        std::string file_path = filename + "/generator-database.json";
        nlohmann::json jsonOutput;

        // Iterate over the CallMap
        for (const auto& call : GenMap) {
            // Create a JSON object for each call
            nlohmann::json callObject;
            callObject["Function"] = call.Function;
            callObject["Service"] = call.Service;
            callObject["Include"] = call.includes;

            for (const auto& argumentPair : call.Arguments) {
                // Create a JSON object for each argument
                nlohmann::json argObject;
                const Argument& arg = argumentPair.second;
                argObject["data_type"] = arg.data_type;
                argObject["variable"] = arg.variable;
                argObject["assignment"] = arg.assignment;
                argObject["arg_dir"] = arg.arg_dir;
                argObject["arg_type"] = arg.arg_type;
                argObject["usage"] = arg.usage;

                callObject["Arguments"][argumentPair.first] = argObject;
            }

            // Add the call object to the JSON output
            jsonOutput.push_back(callObject);
        }

        // Write the JSON object to a file
        std::ofstream outFile(file_path);
        outFile << jsonOutput.dump(4);
        outFile.close();
    }

    /*
        Debugging function to print the Arg Map to stdout
    */
    void printCallMap(const std::vector<Call> &calls) {
        for (const auto &callEntry : calls) {
            llvm::outs() << "Function: " << callEntry.Function << "\n";
            llvm::outs() << "Service: " << callEntry.Service << "\n";
            
            for (const auto &varEntry : callEntry.Arguments) {
                llvm::outs() << "\tArgument: " << varEntry.first << "\n";
                Argument Arg = varEntry.second;
                llvm::outs() << "\t\tData_Type: " << Arg.data_type << "\n";
                llvm::outs() << "\t\tArg_Type: " << Arg.arg_type << "\n";
                llvm::outs() << "\t\tArg_Name: " << Arg.variable << "\n";
                llvm::outs() << "\t\tArg_Assign: " << Arg.assignment << "\n";
                llvm::outs() << "\t\tArg_Direction: " << Arg.arg_dir << "\n";
                llvm::outs() << "\t\tArg_Usage: " << Arg.usage << "\n";
            }
        }
    }

    /*
        Read input file that contains the functions to analyze
        and store them in the FunctionNames set
    */
    std::set<std::string> processFunctionNames(const std::string& filename) {
        std::ifstream file(filename);

        if (!file.is_open()) {
            std::cerr << "Error opening file: " << filename << std::endl;
            exit(1);
        }
        FunctionNames.clear();
        std::string line;
        while (std::getline(file, line)) {
            // Remove leading and trailing whitespace
            line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](int ch) { return !std::isspace(ch); }));
            line.erase(std::find_if(line.rbegin(), line.rend(), [](int ch) { return !std::isspace(ch); }).base(), line.end());

            // Remove extra whitespace between words
            line = std::regex_replace(line, std::regex("\\s+"), " ");

            if (!line.empty()) {
                FunctionNames.insert(line);
            }
        }

        file.close();
        return FunctionNames;
    }
}; // FileOps namespace

#endif