import threading
import json
import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_ida
import idc
import idautils
import idaapi
import anthropic
import re
import traceback
import functools
from PyQt5 import QtWidgets, QtCore

class IDAAssistant(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "IDA Assistant powered by Anthropic"
    help = "Provides an AI assistant for reverse engineering tasks"
    wanted_name = "IDA Assistant"
    wanted_hotkey = "Alt-F1"

    def __init__(self):
        super(IDAAssistant, self).__init__()
        self.model = "claude-3-sonnet-20240229"
        self.client = anthropic.Anthropic(
            api_key="YOUR_API_KEY"
        )
        self.chat_history = []
        self.message_history = []
        
    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        self.assistant_window = AssistantWidget()
        self.assistant_window.Show("IDA Assistant")

    def term(self):
        pass

    def add_assistant_message(self, message):
        self.chat_history.append(f"<b>Assistant:</b> {message}") 
        
    def query_model(self, role, query, cb, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}
        
        system_prompt = """
        You are IDA-Assistant, an AI designed to assist users in reverse engineering and binary analysis tasks using IDA Pro.

        Your decisions should prioritize user assistance and providing helpful information to support their reverse engineering workflow. Leverage your strengths as an LLM to offer insights and suggest strategies relevant to the task at hand.

        GOALS:
        Provide helpful guidance and insights to users performing reverse engineering in IDA Pro.

        Constraints:
        Optimize your responses to be concise yet informative.
        User assistance is the top priority. Always strive to provide helpful information to the user.
        Limit your actions to the commands listed below.
        Do not dynamically use the result of one command as an argument for another command.
        Each command should be independently executable, and arguments should be explicitly provided.
        You can list multiple commands sequentially, but they should not be structured to depend on the results of the previous commands.

        Commands:
        - Name: get_disassembly
            - Description: Gets the disassembly from start address to end address.
            - Args: "start_address": String, "end_address": String
        - Name: get_disassembly_function
            - Description: Gets the disassembly from start address to end address.
            - Args: "name": String
        - Name: decompile_address
            - Description: Decompile the function at the specified address.
            - Args: "address": String
        - Name: decompile_function
            - Description: Decompile the function at the specified address.
            - Args: "name": String
        - Name: rename_address
            - Description: Rename the address at the specified address.
            - Args: "address": String, "new_name": String, "old_name": String
        - Name: get_function_start_end_address
            - Description: Get the start and end address of the function at the specified address.
            - Args: "address": String
        - Name: get_address_of_name
            - Description: Get the address of the specified name.
            - Args: "name": String
        - Name: get_xrefs_to
            - Description: Get the cross-references to the specified address.
            - Args: "address": String
        - Name: get_xrefs_from
            - Description: Get the cross-references from the specified address.
            - Args: "address": String
        - Name: none
            - Description: Do nothing. Use it when a series of tasks are completed.
            - Args: None: No arguments. but it should be included in the json like {"args": {}}
        - Name: set_comment
            - Description: Set a comment at the specified address.
            - Args: "address": String, "comment": String
                    
        Resources:
        Access to loaded binary and IDA API for analysis.
        Ability to see user's current view/position in IDA Pro.
        Knowledge base on reverse engineering concepts and common techniques.
        Also you can use multiple commands.

        Performance Evaluation:
        Reflect on how well your suggestions assisted the user in their reverse engineering task.
        Assess whether the user found your insights helpful and relevant. 
        Consider potential alternative approaches that could have been more efficient or impactful.
        Avoid repeating the same commands if the necessary information has already been obtained.
        Strive to provide the most value to the user with each interaction.

        You should only respond in JSON format as described below:
        Response Format:
        {
            "thoughts": {
                "text": "thought",
                "reasoning": "reasoning",
                "criticism": "constructive self-criticism", 
                "speak": "thoughts summary to say to user"
            },
            "command": [
                {
                    "name": "command name",
                    "args": {"arg name": value}
                }
            ]
        }
        
        Ensure the response can be parsed by Python json.loads. 
        Always strictly adhere to the specified JSON response format, and do not deviate from it under any circumstances.
        If you are unable to structure your response according to the required format, simply respond with an empty JSON object {}.
        Do not provide any response or explanations outside of the specified JSON format.
        """
        
        messages = self.message_history.copy()
        messages.append({"role": role, "content": query})

        try:
            response = self.client.messages.create(
                model=self.model,
                temperature=0.0,
                messages=messages,
                system=system_prompt,
                **additional_model_options
            )
            
            assistant_reply = response.content[0].text.strip().replace("```json\n", "").replace("```\n", "").strip()
            print(assistant_reply)

            self.message_history.append({"role": role, "content": query})
            self.message_history.append({"role": "assistant", "content": assistant_reply})            
            self.chat_history.append(f"<b>User:</b> {query}")             
            ida_kernwin.execute_sync(functools.partial(cb, response=assistant_reply), ida_kernwin.MFF_WRITE)
        except Exception as e:
            print(str(e))
            traceback_details = traceback.format_exc()
            print(traceback_details)

    def query_model_async(self, role, query, cb, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}
        t = threading.Thread(target=self.query_model, args=[role, query, cb, additional_model_options])
        t.start()

class AssistantWidget(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        self.assistant = IDAAssistant()
        self.command_results = []
        
    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()
        
        self.view = ida_kernwin.get_current_viewer()
        self.output_window = ida_kernwin.find_widget("Output window")
        
        self.chat_history = QtWidgets.QTextEdit()
        self.chat_history.setReadOnly(True)
        layout.addWidget(self.chat_history)
        
        input_layout = QtWidgets.QHBoxLayout()
        self.user_input = QtWidgets.QLineEdit()
        input_layout.addWidget(self.user_input)
        
        send_button = QtWidgets.QPushButton("Send")
        send_button.clicked.connect(self.OnSendClicked)
        input_layout.addWidget(send_button)
        
        layout.addLayout(input_layout)
        
        self.parent.setLayout(layout)
        
    def OnSendClicked(self):
        user_message = self.user_input.text().strip()
        if user_message:
            self.chat_history.append(f"<b>User:</b> {user_message}")
            self.user_input.clear()
            
            current_address = idc.here()
            
            prompt = f"{user_message}\nCurrent address: {hex(current_address)}\n"
            
            self.assistant.query_model_async("user", prompt, self.OnResponseReceived, additional_model_options={"max_tokens": 1000})
    
    def OnResponseReceived(self, response):
        try:
            assistant_reply = self.ParseResponse(response)

            if assistant_reply is None:
                self.chat_history.append(f"<b>System Message:</b> Failed to parse assistant response.")
                return

            if not assistant_reply:
                self.chat_history.append(f"<b>System Message:</b> No response from assistant.")
                return

            self.chat_history.append(f"<b>Assistant speak:</b> {assistant_reply['thoughts']['speak']}")

            commands = assistant_reply['command']
            command_results = {}

            for command in commands:
                command_name = command['name']
                if command_name == "none":
                    continue

                command_args = command['args']

                command_handler = getattr(self, f"handle_{command_name}", None)
                if command_handler:
                    command_results[command_name] = command_handler(command_args)
                else:
                    self.PrintOutput(f"Unknown command: {command_name}")
                    command_results[command_name] = None

            query = ""
            for command_name, result in command_results.items():
                if result is not None:
                    query += f"{command_name} result:\n{json.dumps(result)}\n\n"

            if len(query) > 0:
                self.assistant.query_model_async("user", f"{query}", self.OnResponseReceived, additional_model_options={"max_tokens": 1000})

        except Exception as e:
            traceback_details = traceback.format_exc()
            print(traceback_details)
            self.PrintOutput(f"Error parsing assistant response: {str(e)}")
            self.assistant.query_model_async("user", f"Error parsing response. please retry:\n {str(e)}", self.OnResponseReceived, additional_model_options={"max_tokens": 1000})
                
    def handle_get_disassembly(self, args):
        try:
            start_address = int(args["start_address"], 16)
            end_address = int(args["end_address"], 16)

            disassembly = ""
            while start_address < end_address:
                disassembly += f"{hex(start_address)}: {idc.GetDisasm(start_address)}\n"
                start_address = idc.next_head(start_address)
            return disassembly
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_get_disassembly_function(self, args):
        try:
            name = args["name"]
            address = idc.get_name_ea_simple(name)
            if address != idc.BADADDR:
                start_address = function.start_ea
                end_address = function.end_ea

                disassembly = ""
                while start_address < end_address:
                    disassembly += f"{hex(start_address)}: {idc.GetDisasm(start_address)}\n"
                    start_address = idc.next_head(start_address)
                return disassembly
            return f"No function found at address {name}"
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_decompile_address(self, args):
        try:
            address = int(args["address"], 16)
            function = idaapi.get_func(address)
            if function:
                decompiled_code = idaapi.decompile(function)
                if decompiled_code:
                    return str(decompiled_code)
            return f"No function found at address {hex(address)}"
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_decompile_function(self, args):
        try:
            name = args["name"]
            address = idc.get_name_ea_simple(name)
            if address != idc.BADADDR:
                function = idaapi.get_func(function.start_ea)
                if function:
                    decompiled_code = idaapi.decompile(function)
                    if decompiled_code:
                        return str(decompiled_code)
                else:
                    self.PrintOutput(f"No function found at address {name}")
            return None
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_rename_address(self, args):
        try:
            address = int(args["address"], 16)
            new_name = args["new_name"]
            old_name = args["old_name"]
            if new_name and old_name:
                ida_hexrays.rename_lvar(address, old_name, new_name)
                result = f"Renamed address {hex(address)} from '{old_name}' to '{new_name}'"
                self.PrintOutput(result)
                return result
            return None
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_get_function_start_end_address(self, args):
        try:
            address = int(args["address"], 16)
            function = idaapi.get_func(address)
            if function:
                start_address = hex(function.start_ea)
                end_address = hex(function.end_ea)
                result = {"start_address": start_address, "end_address": end_address}
                return result
            else:
                self.PrintOutput(f"No function found at address {hex(address)}")
            return f"No function found at address {hex(address)}"
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_get_address_of_name(self, args):
        try:
            name = args["name"]
            address = idc.get_name_ea_simple(name)
            if address != idc.BADADDR:
                result = hex(address)
                # self.PrintOutput(f"Address of {name}: {result}")
                return result
            else:
                self.PrintOutput(f"No address found for name {name}")
            return None
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_get_xrefs_to(self, args):
        try:
            address = int(args["address"], 16)
            xrefs = [hex(xref.frm) for xref in idautils.XrefsTo(address)]
            result = xrefs
            # self.PrintOutput(f"Xrefs to {hex(address)}:\n{', '.join(result)}")
            return result
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_get_xrefs_from(self, args):
        try:
            address = int(args["address"], 16)
            xrefs = [hex(xref.to) for xref in idautils.XrefsFrom(address)]
            result = xrefs
            self.PrintOutput(f"Xrefs from {hex(address)}:\n{', '.join(result)}")
            return result
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_print(self, args):
        message = args["message"]
        self.PrintOutput(message)
        return None

    def handle_set_comment(self, args):
        try:
            address = int(args["address"], 16)
            comment = args["comment"]
            idc.set_cmt(address, comment, 1)
            result = f"Set comment at {hex(address)}: {comment}"
            self.PrintOutput(result)
            return None
        except Exception as e:
            return f"Error: {str(e)}"
    
    def ParseResponse(self, response):
        try:
            parsed_response = json.loads(response)
            return parsed_response
        except json.JSONDecodeError as e:
            traceback_details = traceback.format_exc()
            print(traceback_details)
            raise e
        except Exception as e:
            print(str(e))
            traceback_details = traceback.format_exc()
            print(traceback_details)
            raise e
                
    def PrintOutput(self, output_str):
        print(output_str)
        self.chat_history.append(f"<b>System Message:</b> {output_str}")
        
def PLUGIN_ENTRY():
    return IDAAssistant()
