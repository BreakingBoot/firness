#ifndef _ANALYZE_EDK2_H_
#define _ANALYZE_EDK2_H_

struct Parameter
{
    std::string Variable;
    std::string Type;
    std::string Identifier;
    std::string Fuzzable;
    std::string CallValue;
    bool empty() const{
        return Variable.empty() && Type.empty() && Identifier.empty() && Fuzzable.empty() && CallValue.empty();
    }
    int filled() const{
        int number = 0;
        if (!Variable.empty())
            number++;
        if (!Type.empty())
            number++;
        if (!Identifier.empty())
            number++;
        if (!Fuzzable.empty())
            number++;
        if (!CallValue.empty())
            number++;
        return number;
    }
};

struct Service
{
    std::string Service;
    std::string ServiceType;
    std::string ServiceGUID;
    std::string ServiceDefName;
    std::vector<Parameter> Parameters;

    int get_score() const{
        int score = 0;
        for (Parameter p: Parameters)
        {
            score += p.filled();
        }
        return score;
    }
};

#endif