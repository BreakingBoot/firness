from jinja2 import Template
import re
import json

class CodeGeneration:

    def __init__(self, analyzed_services, well_formed_parameters, function_grouping):
        self.analyzed_services = analyzed_services["ServicesInfo"]
        self.includes = analyzed_services["Includes"]
        self.well_formed_parameters = well_formed_parameters
        self.case_definitions = self.create_case_definitions()
        self.function_grouping = function_grouping

    def create_case_definitions(self):
        case_definitions = []
        for function_case in self.analyzed_services:
            case_definitions.append(self.add_underscore_before_uppercase(function_case["Service"]).upper())
        return case_definitions

    def generate_function_harness(self):
        self.generate_code()
        self.generate_header()

    def generate_total_harness(self):
        self.generate_code()
        self.generate_header()
        self.generate_main()
        self.generate_ini()

    def add_underscore_before_uppercase(self, s):
        s = re.sub(r'([A-Z])', r'_\1', s)
        return s[1:] if s.startswith('_') else s

    def generate_code(self):
        main = Template('''
        #include "{{ function_name }}.h"

        EFI_STATUS
        EFIAPI
        {{ function_name }}(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable 
            ) 
        {
            EFI_STATUS Status = EFI_SUCCESS;
            DEBUG ((DEBUG_ERROR, "FUZZING: {{ function_name }}\\n"));

            UINTN Service = 0;
            ReadInput(Input, 1, &Service);

            switch(Service%{{ analyzed_services|length }})
            {
                {% for function in analyzed_services %}case {{ case_definitions[loop.index0] }}:
                    Status = Fuzz{{ function["Service"] }}(Input, SystemTable);
                    break;
                {% endfor %}
            }
            return Status;
        }
        {% for function in analyzed_services %}
        EFI_STATUS
        EFIAPI
        Fuzz{{ function["Service"] }}(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            )
        {
            EFI_STATUS Status = EFI_SUCCESS;
            DEBUG ((DEBUG_ERROR, "FUZZING: {{ function["Service"] }}\\n"));
            {% for parameter in function['Parameters'] %}{% if parameter["Identifier"] == "*" %}{{ parameter["Type"] }} {{ parameter["Identifier"] }}{{ parameter["Variable"] }} = AllocatePool(sizeof({{ parameter["Type"] }}));
            {% else %}{{ parameter["Type"] }} {{ parameter["Identifier"] }}{{ parameter["Variable"] }} = 0; {% endif %}
            {% if parameter["Fuzzable"] == "YES" %}ReadInput(Input, sizeof({{ parameter["Type"] }}), &{{ parameter["Variable"] }});{% endif %}
            {% endfor %}

            {% if function["ServiceType"] == "Protocol" %}
            Status = SystemTable->BootServices->LocateProtocol(&{{ function["ServiceGUID"] }}, NULL, (VOID **)&{{ function["ServiceDefName"] }});
            Status = {{ function["ServiceDefName"] }}->{{ function["Service"] }}({% for parameter in function['Parameters'] %}{{ parameter["CallValue"] }}{% if not loop.last %}, {% endif %}{% endfor %});
            {% elif function["ServiceType"] == "Runtime" %}
            Status = SystemTable->RuntimeServices->{{ function["Service"] }}({% for parameter in function['Parameters'] %}{{ parameter["CallValue"] }}{% if not loop.last %}, {% endif %}{% endfor %});
            {% endif %}
            
            return Status;
        }
        {% endfor %}
        ''')
        with open(self.function_grouping+'.c', 'w') as f:
            f.write(main.render(function_name=self.function_grouping, analyzed_services=self.analyzed_services, case_definitions=self.case_definitions))

    def generate_header(self):
        header = Template('''
        {% for include in includes %}#include "{{ include }}"
        {% endfor %}

        {% for define in case_definitions %}#define {{ define }} {{ loop.index0 }}
        {% endfor %}

        EFI_STATUS
        EFIAPI
        {{ function_name }}(
            IN INPUT_BUFFER *Input
            );
        {% for function in analyzed_services %}
        EFI_STATUS
        EFIAPI
        Fuzz{{ function["Service"] }}(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            );
        {% endfor %}
        ''')
        with open(self.function_grouping+'.h', 'w') as f:
            f.write(header.render(function_name=self.function_grouping, analyzed_services=self.analyzed_services, case_definitions=self.case_definitions, includes=self.includes))

    def generate_ini(self):
        ini = Template('''
        {% for include in includes %}#include "{{ include }}"
        {% endfor %}

        {% for define in case_definitions %}#define {{ define }} {{ loop.index0 }}
        {% endfor %}

        EFI_STATUS
        EFIAPI
        {{ function_name }}(
            IN INPUT_BUFFER *Input
            );
        {% for function in analyzed_services %}
        EFI_STATUS
        EFIAPI
        Fuzz{{ function["Service"] }}(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            );
        {% endfor %}
        ''')
        with open(self.function_grouping+'.h', 'w') as f:
            f.write(ini.render(function_name=self.function_grouping, analyzed_services=self.analyzed_services, case_definitions=self.case_definitions, includes=self.includes))

    def generate_main(self):
        main = Template('''
        {% for include in includes %}#include "{{ include }}"
        {% endfor %}

        {% for define in case_definitions %}#define {{ define }} {{ loop.index0 }}
        {% endfor %}

        EFI_STATUS
        EFIAPI
        {{ function_name }}(
            IN INPUT_BUFFER *Input
            );
        {% for function in analyzed_services %}
        EFI_STATUS
        EFIAPI
        Fuzz{{ function["Service"] }}(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            );
        {% endfor %}
        ''')
        with open(self.function_grouping+'.h', 'w') as f:
            f.write(main.render(function_name=self.function_grouping, analyzed_services=self.analyzed_services, case_definitions=self.case_definitions, includes=self.includes))