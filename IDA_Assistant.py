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
            api_key="<YOUR API KEY>"
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
        
    def query_model(self, query, cb, additional_model_options=None):
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

        Commands:
        1. Name: get_disassembly
          - Description: Gets the dispassembly from start address to end address.
          - Args: "start_address": "<address>", "end_address": "<address>"
        2. Name: decompile
            - Description: Decompile the function at the specified address.
            - Args: "address": "<address>"
        3. Name: rename_address
            - Description: Rename the address at the specified address.
            - Args: "address": "<address>", "new_name": "<new_name>", "old_name": "<old_name>"
        4. Name: get_function_start_end_address
            - Description: Get the start and end address of the function at the specified address.
            - Args: "address": "<address>"
        5. Name: get_address_of_name
            - Description: Get the address of the specified name.
            - Args: "name": "<name>"
        6. Name: get_xrefs_to
            - Description: Get the cross-references to the specified address.
            - Args: "address": "<address>"
        7. Name: get_xrefs_from
            - Description: Get the cross-references from the specified address.
            - Args: "address": "<address>"
        8. Name: print
            - Description: Print the specified message. Please be careful because it's a string that will be included in the json
            - Args: "message": "<message>"
        9. Name: none
            - Description: Do nothing. Use it when a series of tasks are completed.
            - Args: None
        10. Name: set_comment
            - Description: Set a comment at the specified address.
            - Args: "address": "<address>", "comment": "<comment>"
                    
        Resources:
        Access to loaded binary and IDA API for analysis.
        Ability to see user's current view/position in IDA Pro.
        Knowledge base on reverse engineering concepts and common techniques.
        Also you can use multiple commands.
        Memory of previous commands executed and their results during the current conversation.

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
                    "args": {"arg name": "value"}
                }
            ]
        }

        Ensure the response can be parsed by Python json.loads. 
        Always strictly adhere to the specified JSON response format, and do not deviate from it under any circumstances.
        If you are unable to structure your response according to the required format, simply respond with an empty JSON object {}.
        Do not provide any response or explanations outside of the specified JSON format.
        """
        
        messages = self.message_history.copy()
        messages.append({"role": "user", "content": query})

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

            self.message_history.append({"role": "user", "content": query})
            self.message_history.append({"role": "assistant", "content": assistant_reply})            
            self.chat_history.append(f"<b>User:</b> {query}")             
            ida_kernwin.execute_sync(functools.partial(cb, response=assistant_reply), ida_kernwin.MFF_WRITE)
        except Exception as e:
            print(str(e))
            traceback_details = traceback.format_exc()
            print(traceback_details)

    def query_model_async(self, query, cb, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}
        t = threading.Thread(target=self.query_model, args=[query, cb, additional_model_options])
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
            
            self.assistant.query_model_async(prompt, self.OnResponseReceived, additional_model_options={"max_tokens": 1000})
    
    def OnResponseReceived(self, response):
        try:
            assistant_reply = self.ParseResponse(response)

            # check assistant_reply is {}
            if not assistant_reply:
                self.chat_history.append(f"<b>System Message:</b> No response from assistant.")
                return
            
            self.chat_history.append(f"<b>Assistant speak:</b> {assistant_reply['thoughts']['speak']}")

            commands = assistant_reply['command']

            command_results = []
            for command in commands:
                command_name = command['name']
                if command_name == "none":
                    return
                
                if command.get("reason") != None:
                    self.PrintOutput(f"Command Reasoning: {command['reason']}")
                
                command_args = command['args']
                
                if command_name == "get_disassembly":
                    start_address = int(command_args["start_address"], 16)
                    end_address = int(command_args["end_address"], 16)
                    
                    disassembly = ""
                    while start_address < end_address:
                        disassembly += f"{hex(start_address)}: {idc.GetDisasm(start_address)}\n"
                        start_address = idc.next_head(start_address)                    
                    command_results.append(f"get_disassembly result:\n{disassembly}")
                elif command_name == "decompile":
                    address = int(command_args["address"], 16)
                    function = idc.get_func_attr(address, idc.FUNCATTR_START)
                    if function:
                        decompiled_code = str(ida_hexrays.decompile(function))
                        command_results.append(f"decompile result:\n{decompiled_code}")
                    else:
                        command_results.append(f"decompile result:\nNo function found at address {hex(address)}")
                        self.PrintOutput(f"No function found at address {hex(address)}")
                elif command_name == "rename_address":
                    address = int(command_args["address"], 16)
                    new_name = command_args["new_name"]
                    old_name = command_args["old_name"]
                    if new_name and old_name:
                        ida_hexrays.rename_lvar(address, old_name, new_name)
                        result = f"Renamed function at {hex(address)}: '{old_name}' to '{new_name}'"
                        self.PrintOutput(result)
                        command_results.append(f"rename_address result:\n{result}")
                elif command_name == "get_function_start_end_address":
                    address = int(command_args["address"], 16)
                    function = idc.get_func_attr(address, idc.FUNCATTR_START)
                    if function:
                        start_address = idc.get_func_attr(address, idc.FUNCATTR_START)
                        end_address = idc.get_func_attr(address, idc.FUNCATTR_END)
                        result = f"Function at {hex(address)} starts at {hex(start_address)} and ends at {hex(end_address)}"
                        command_results.append(f"get_function_start_end_address result:\n{result}")
                        self.PrintOutput(result)
                    else:
                        command_results.append(f"get_function_start_end_address result:\nNo function found at address {hex(address)}")
                        self.PrintOutput(f"No function found at address {hex(address)}")
                elif command_name == "get_address_of_name":
                    name = command_args["name"]
                    address = idc.get_name_ea_simple(name)
                    if address != idc.BADADDR:
                        result = f"Address of {name} is {hex(address)}"
                        self.PrintOutput(result)
                        command_results.append(f"get_address_of_name result:\n{result}")
                    else:
                        command_results.append(f"get_address_of_name result:\nNo address found for name {name}")
                        self.PrintOutput(f"No address found for name {name}")
                elif command_name == "get_xrefs_to":
                    address = int(command_args["address"], 16)
                    xrefs = idautils.XrefsTo(address)
                    result = f"Xrefs to {hex(address)}:\n"
                    for xref in xrefs:
                        result += f"{hex(xref.frm)}\n"
                    command_results.append(f"get_xrefs_to result:\n{result}")
                    self.PrintOutput(result)
                elif command_name == "get_xrefs_from":
                    address = int(command_args["address"], 16)
                    xrefs = idautils.XrefsFrom(address)
                    result = f"Xrefs from {hex(address)}:\n"
                    for xref in xrefs:
                        result += f"{hex(xref.to)}\n"
                    command_results.append(f"get_xrefs_from result:\n{result}")
                    self.PrintOutput(result)
                    pass
                elif command_name == "print":
                    message = command_args["message"]
                    self.PrintOutput(message)
                elif command_name == "set_comment":
                    address = int(command_args["address"], 16)
                    comment = command_args["comment"]
                    idc.set_cmt(address, comment, 1)
                    result = f"Set comment at {hex(address)}: {comment}"
                    self.PrintOutput(result)
                else:
                    self.PrintOutput(f"Unknown command: {command_name}")
            
            query = ""
            for result in command_results:
                query += result + "\n\n"
            
            if len(command_results) > 0:
                self.assistant.query_model_async(f"{query}", self.OnResponseReceived, additional_model_options={"max_tokens": 1000})

        except Exception as e:
            if "Expecting value: line" in str(e) or "Extra data: line" in str(e):
                self.chat_history.append(f"<b>Assistant speak:</b> {response}")
            else:
                self.PrintOutput(f"Error parsing assistant response: {str(e)}")
            
    def ParseResponse(self, response):
        return json.loads(response)
                
    def PrintOutput(self, output_str):
        print(output_str)
        self.chat_history.append(f"<b>System Message:</b> {output_str}")
        
def PLUGIN_ENTRY():
    return IDAAssistant()
