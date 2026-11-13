#ifndef __FILE_OP_HELPERS_H__
#define __FILE_OP_HELPERS_H__

#include "Globals.h"
#include <nlohmann/json.hpp>


namespace FileOps {
    void outputMacros(const std::string &filename, const std::map<std::string, MacroDef>& macros) {
        std::string file_path = filename + "/macros.json";
        nlohmann::json j;
        for (const auto& pair : macros) {
            const MacroDef& macro = pair.second;
            nlohmann::json macroJson;
            macroJson["Name"] = macro.Name;
            macroJson["File"] = macro.File;
            macroJson["Value"] = macro.Value;
            j.push_back(macroJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }
    
    /*
        Responsible for writing the typedef aliases
        gathered from the analysis to a json output file called aliases

    */
    void outputTypedefs(const std::string &filename, const std::set<std::pair<std::string, std::string>>& types) {
        std::string file_path = filename + "/aliases.json";
        nlohmann::json j;
        for (const auto& pair : types) {
            j[pair.first] = pair.second;
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
            typeJson["File"] = typeData.File;
            typeJson["Fields"] = fieldsJson;

            j.push_back(typeJson);
        }

        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    /*
        Responsible for writing the function information
        gathered from the analysis to a json output file called functions
    */
    void outputFunctionDecl(const std::string &filename, const std::vector<Function>& functions) {
        std::string file_path = filename + "/functions.json";
        nlohmann::json j;
        for (const auto& function : functions) {
            nlohmann::json functionJson;
            functionJson["Function"] = function.FunctionName;
            functionJson["ReturnType"] = function.return_type;
            nlohmann::json parametersJson;
            for (const auto& pair : function.Parameters) {
                nlohmann::json paramJson;
                const Argument& arg = pair.second;
                paramJson["arg_dir"] = arg.arg_dir;
                paramJson["is_optional"] = arg.is_optional;
                paramJson["arg_type"] = arg.arg_type;
                paramJson["variable"] = arg.variable;
                paramJson["data_type"] = arg.data_type;
                paramJson["assignment"] = arg.assignment;
                paramJson["usage"] = arg.usage;
                paramJson["potential_outputs"] = arg.potential_outputs;
                parametersJson[pair.first] = paramJson;
            }
            functionJson["Parameters"] = parametersJson;
            functionJson["File"] = function.File;
            functionJson["Includes"] = function.includes;
            j.push_back(functionJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    void outputSmiFunctionGuidMap(const std::string& filename, const std::map<std::string, SmiInfo>& smiFunctionGuidMap) {
        std::string file_path = filename + "/smi-function-guid-map.json";
        nlohmann::json j;
        unsigned total = 0, no_type = 0, not_guid = 0, gated_fields = 0;
        std::map<std::string, unsigned> by_dispatch;

        for (const auto& pair : smiFunctionGuidMap) {
            total++;
            const SmiInfo& smiInfo = pair.second;
            by_dispatch[smiInfo.Dispatch.empty() ? "unrecognised" : smiInfo.Dispatch]++;

            //
            // Only the GUID-dispatched handlers go in this file, because this file is what
            // the generator turns into harnesses and a harness drives a handler by sending
            // an EFI_SMM_COMMUNICATE_HEADER carrying its GUID. A handler on a root
            // dispatcher has no GUID -- it is reached by a write to the software MMI port,
            // or by an S-state transition -- and its CommBuffer is built by the dispatcher
            // rather than copied from the caller. Emitting one here would generate a
            // harness that fabricates an input the hardware cannot produce and reports
            // whatever it found against the wrong cause.
            //
            // They are not discarded: every handler, dispatch kind included, goes to
            // smi-handler-inventory.json below, so the count of what exists stays honest
            // even while the count of what can be driven does not grow.
            //
            if (!smiInfo.Dispatch.empty() && smiInfo.Dispatch != "SmiHandlerRegister") {
                not_guid++;
                continue;
            }
            if(smiInfo.Type == "") { no_type++; continue; } // Skip if Guid is empty
            nlohmann::json smiJson;
            smiJson["Guid"] = smiInfo.Guid;
            smiJson["Type"] = smiInfo.Type;
            smiJson["Dispatch"] = smiInfo.Dispatch;
            //
            // The protocol whose buffer this handler insists on, when it insists. The
            // generator locates it instead of allocating out of the PI SMM communication
            // region; without it the handler rejects every input on an address compare.
            //
            smiJson["BufferProtocol"] = smiInfo.BufferProtocol;
            //
            // The constants this handler tests each field against, so the generator can
            // offer them through the field's selector byte instead of waiting for a raw
            // read to land on one. See SmiInfo::FieldConstants for the arithmetic.
            //
            nlohmann::json constants = nlohmann::json::object();
            for (const auto& field : smiInfo.FieldConstants) {
                nlohmann::json byName = nlohmann::json::object();
                for (const auto& one : field.second) {
                    byName[one.first] = one.second;   // spelling -> integer value
                }
                constants[field.first] = byName;
            }
            smiJson["FieldConstants"] = constants;
            gated_fields += smiInfo.FieldConstants.size();
            j[pair.first] = smiJson;
        }

        // silent unless the smi pass actually ran, so a normal analysis is unchanged
        if (SmiEnabled) {
            llvm::outs() << "SMI handlers: " << total << " found, " << not_guid
                         << " not addressable by GUID, " << no_type
                         << " dropped for an unresolved CommBuffer type, "
                         << (total - not_guid - no_type) << " written, " << gated_fields
                         << " field(s) with the constants the source tests them against\n";
            for (const auto& pair : by_dispatch) {
                llvm::outs() << "  " << pair.first << ": " << pair.second << "\n";
            }
        }

        std::ofstream file(file_path);
        file << j.dump(4);
        file.close();

        //
        // The full inventory, including the handlers the generator cannot drive. This is
        // the file to read when asking "how much of the SMI surface is covered" -- the
        // guid map alone answers a narrower question and reads as the whole of it.
        //
        nlohmann::json inv;
        for (const auto& pair : smiFunctionGuidMap) {
            const SmiInfo& smiInfo = pair.second;
            nlohmann::json entry;
            entry["Guid"] = smiInfo.Guid;
            entry["Type"] = smiInfo.Type;
            entry["File"] = smiInfo.File;
            entry["Dispatch"] = smiInfo.Dispatch;
            entry["BufferProtocol"] = smiInfo.BufferProtocol;
            //
            // What this analysis can say on its own: the handler is reached by GUID and
            // its comm buffer has a type to fill. It is not the coverage answer, and
            // naming it as one makes the file disagree with the harnesses built from it.
            // The generator runs after this and both adds handlers -- re-deriving a GUID
            // and a payload type from the source for ones recorded without a type -- and
            // drops others whose payload it cannot carry into the harness, so the set it
            // ends up driving is known only there. harness_generator writes the coverage
            // field back into this file once that set is final.
            //
            entry["AnalyzerTyped"] = (smiInfo.Dispatch == "SmiHandlerRegister" ||
                                      smiInfo.Dispatch.empty()) && smiInfo.Type != "";
            inv[pair.first] = entry;
        }
        std::ofstream invFile(filename + "/smi-handler-inventory.json");
        invFile << inv.dump(4);
        invFile.close();
    }

    /*
        Every call made from inside an SMI handler, written to smi-call-edges.json.

        This is the inverse of outputCallMap. That one answers "where is function F
        called from", which is what a protocol campaign needs. An SMI handler is never
        called by name -- the SMM core dispatches a registered pointer -- so the useful
        question is the other way round: "what does handler H call, and with what".

        The record is deliberately the same shape outputCallMap writes, so a reader that
        already parses call-database.json needs no new parser. What matters for a
        cross-module defect is the pair (Service, Function) plus each argument's
        assignment: an SMI handler that hands a comm-buffer-derived pointer to another
        module's protocol has skipped whatever validation that module does on its own
        SMI entry path. Measured on EVAL-1, that is exactly RWVariableHandler calling
        mSmmVariable->SmmSetVariable with VarName = (CHAR16 *)CommData->Data -- issues
        #47 and #48, found by fuzzing only after 110255 iterations and reported against
        the callee's module, when the edge was in the source the whole time.

        No judgement is made here on purpose. Deciding which edge is dangerous needs the
        handler's validation to be read, and that belongs in analyze_smi.py where it can
        be changed and tested without rebuilding the analyzer.
    */
    void outputSmiCallEdges(const std::string& filename, const std::vector<Call>& edges) {
        std::string file_path = filename + "/smi-call-edges.json";
        nlohmann::json jsonOutput = nlohmann::json::array();

        std::set<std::string> handlers;
        for (const auto& call : edges) {
            nlohmann::json callObject;
            callObject["Function"] = call.Function;
            callObject["Service"] = call.Service;
            callObject["EnclosingFunction"] = call.EnclosingFunction;
            callObject["EnclosingFile"] = call.EnclosingFile;
            callObject["CallOrder"] = call.CallOrder;
            callObject["ReturnType"] = call.return_type;
            //
            // The enclosing caller-data condition, or "" when the call is unconditional.
            // Written for every edge, not only the gated ones, so a consumer can tell "no
            // gate" from "this analyzer did not look".
            //
            callObject["CallerGate"] = call.CallerGate;
            handlers.insert(call.EnclosingFunction);

            for (const auto& argumentPair : call.Arguments) {
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
            jsonOutput.push_back(callObject);
        }

        if (SmiEnabled) {
            size_t gated = 0;
            for (const auto& call : edges) {
                if (!call.CallerGate.empty()) {
                    gated++;
                }
            }
            llvm::outs() << "SMI call edges: " << edges.size() << " call(s) from "
                         << handlers.size() << " handler body(ies), " << gated
                         << " of them reached only when the caller's data says so\n";
        }

        std::ofstream outFile(file_path);
        outFile << jsonOutput.dump(4);
        outFile.close();
    }

    void outputIncludesDependencyGraph(const std::string& filename, const std::map<std::string, std::set<std::string>>& includes) {
        std::string file_path = filename + "/includes.json";
        nlohmann::json j;
        for (const auto& pair : includes) {
            nlohmann::json includeJson;
            includeJson["File"] = pair.first;
            includeJson["Includes"] = pair.second;
            j.push_back(includeJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4);
        file.close();
    }

    /*
        Responsible for writing the function information
        gathered from the analysis to a json output file called functions
    */
    void outputGeneratorDecl(const std::string &filename, const std::vector<Function>& functions) {
        std::string file_path = filename + "/generators.json";
        nlohmann::json j;
        for (const auto& function : functions) {
            nlohmann::json functionJson;
            functionJson["Function"] = function.FunctionName;
            functionJson["ReturnType"] = function.return_type;
            nlohmann::json parametersJson;
            for (const auto& pair : function.Parameters) {
                nlohmann::json paramJson;
                const Argument& arg = pair.second;
                paramJson["arg_dir"] = arg.arg_dir;
                paramJson["is_optional"] = arg.is_optional;
                paramJson["arg_type"] = arg.arg_type;
                paramJson["variable"] = arg.variable;
                paramJson["data_type"] = arg.data_type;
                paramJson["assignment"] = arg.assignment;
                paramJson["usage"] = arg.usage;
                paramJson["potential_outputs"] = arg.potential_outputs;
                parametersJson[pair.first] = paramJson;
            }
            functionJson["Parameters"] = parametersJson;
            functionJson["File"] = function.File;
            functionJson["Includes"] = function.includes;
            j.push_back(functionJson);
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
            callObject["EnclosingFunction"] = call.EnclosingFunction;
            callObject["EnclosingFile"] = call.EnclosingFile;
            callObject["CallOrder"] = call.CallOrder;
            callObject["Include"] = call.includes;
            callObject["ReturnType"] = call.return_type;

            for (const auto& argumentPair : call.Arguments) {
                // Create a JSON object for each argument
                nlohmann::json argObject;
                const Argument& arg = argumentPair.second;
                argObject["data_type"] = arg.data_type;
                argObject["variable"] = arg.variable;
                argObject["assignment"] = arg.assignment;
                argObject["arg_dir"] = arg.arg_dir;
                argObject["is_optional"] = arg.is_optional;
                argObject["arg_type"] = arg.arg_type;
                argObject["usage"] = arg.usage;
                argObject["potential_outputs"] = arg.potential_outputs;

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
            callObject["EnclosingFunction"] = call.EnclosingFunction;
            callObject["EnclosingFile"] = call.EnclosingFile;
            callObject["CallOrder"] = call.CallOrder;
            callObject["Include"] = call.includes;
            callObject["ReturnType"] = call.return_type;

            for (const auto& argumentPair : call.Arguments) {
                // Create a JSON object for each argument
                nlohmann::json argObject;
                const Argument& arg = argumentPair.second;
                argObject["data_type"] = arg.data_type;
                argObject["variable"] = arg.variable;
                argObject["assignment"] = arg.assignment;
                argObject["arg_dir"] = arg.arg_dir;
                argObject["is_optional"] = arg.is_optional;
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
        Responsible for writing the function aliases
        gathered from the analysis to a json output file called function-aliases
    */
   void outputAliases(const std::string &filename, const std::map<std::string, std::set<std::string>>& aliases) {
        std::string file_path = filename + "/function-aliases.json";
        nlohmann::json j;
        for (const auto& pair : aliases) {
            nlohmann::json aliasJson;
            aliasJson["Function"] = pair.first;
            aliasJson["Aliases"] = pair.second;
            j.push_back(aliasJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
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

            // stip any line that containes a [ or a ]
            if (line.find('[') != std::string::npos || line.find(']') != std::string::npos) {
                continue;
            }

            // Remove the protocol name from the function name
            // e.g. gEdkiiIoMmuProtocolGuid:Map -> Map
            size_t colonIndex = line.find(':');
            if (colonIndex != std::string::npos) {
                line = line.substr(colonIndex + 1);
            }

            if (!line.empty()) {
                FunctionNames.insert(line);
            }
        }

        file.close();
        return FunctionNames;
    }

    /*
        Output enums to a json file
    */
    void outputEnums(const std::string& filename, const std::map<std::string, EnumDef>& enums) {
        std::string file_path = filename + "/enums.json";
        nlohmann::json j;
        for (const auto& pair : enums) {
            const EnumDef& enumValues = pair.second;
            nlohmann::json enumJson;
            enumJson["Name"] = pair.first;
            enumJson["Values"] = enumValues.Constants;
            enumJson["File"] = enumValues.File;

            j.push_back(enumJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    /*
        Read input file that contains the functions to analyze
        and store them in the HarnessFunctionNames set
    */
    std::set<std::pair<std::string, std::string>> processHarnessFunctions(const std::string& filename) {
        std::ifstream file(filename);

        if (!file.is_open()) {
            std::cerr << "Error opening file: " << filename << std::endl;
            exit(1);
        }
        HarnessFunctions.clear();
        std::string line;
        std::string function;
        std::string guid = "";
        while (std::getline(file, line)) {
            // Remove leading and trailing whitespace
            line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](int ch) { return !std::isspace(ch); }));
            line.erase(std::find_if(line.rbegin(), line.rend(), [](int ch) { return !std::isspace(ch); }).base(), line.end());

            // Remove extra whitespace between words
            line = std::regex_replace(line, std::regex("\\s+"), " ");

            // stip any line that containes a [ or a ]
            if (line.find('[') != std::string::npos || line.find(']') != std::string::npos) {
                continue;
            }

            // Remove the protocol name from the function name
            // e.g. gEdkiiIoMmuProtocolGuid:Map -> Map
            size_t colonIndex = line.find(':');
            if (colonIndex != std::string::npos) {
                function = line.substr(colonIndex + 1);
                guid = line.substr(0, colonIndex);
            }
            else
            {
                function = line;
            }

            if (!line.empty()) {
                HarnessFunctions.insert(std::make_pair(function, guid));
                function.clear();
                guid = "";
            }
        }

        file.close();
        return HarnessFunctions;
    }

    void GenerateCallGraph(const std::string& filename, const std::map<std::string, std::set<std::string>>& call_graph) {
        std::string file_path = filename + "/call-graph.dot";
        std::ofstream file(file_path);
        file << "digraph G {\n";
        // Add all of the nodes to the graph
        for (const auto& call : call_graph) {
            file << "\t\"" << call.first << "\";\n";
        }

        // Add all the edges to the graph
        for (const auto& call : call_graph) {
            for (const auto& callSite : call.second) {
                file << "\t\"" << call.first << "\" -> \"" << callSite << "\";\n";
            }
        }
        file << "}\n";
        file.close();
    }

    void outputCastMap(const std::string &filename, const std::map<std::string, std::set<std::string>> &castMap) {
        std::string file_path = filename + "/cast-map.json";
        nlohmann::json j;
        for (const auto& pair : castMap) {
            nlohmann::json castJson;
            castJson["Type"] = pair.first;
            castJson["Casts"] = pair.second;
            j.push_back(castJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

}; // FileOps namespace

#endif