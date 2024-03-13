# IDA Assistant
IDA Assistant is an IDA Pro plugin that leverages the power of Anthropic's AI models to assist users in reverse engineering and binary analysis tasks. The plugin integrates with IDA Pro and provides an interactive chat interface where users can ask questions, seek guidance, and receive intelligent suggestions to support their reverse engineering workflow.

## Features
- AI-powered assistance for reverse engineering tasks in IDA Pro
- Interactive chat interface for seamless communication with the AI assistant
### Support for various reverse engineering commands and queries, including:
- Disassembly retrieval
- Function decompilation
- Address renaming
- Function start and end address retrieval
- Address lookup by name
- Cross-reference analysis (xrefs to and from addresses)
- Adding comments to addresses

## Installation
### Clone the repository:
``git clone https://github.com/yourusername/ida-assistant.git``
### Install the required dependencies:
``pip install -r requirements.txt``

Open the ida_assistant.py file and replace <YOUR API KEY> with your actual Anthropic API key.
Copy the ida_assistant.py file to your IDA Pro plugins directory.
Launch IDA Pro and enable the "IDA Assistant" plugin from the "Edit" menu.
## Usage
- Press Alt+F1 or go to "Edit" > "Plugins" > "IDA Assistant" to open the assistant window.
- Type your query or request in the input field and click "Send" or press Enter.
- The AI assistant will analyze your query, execute relevant commands, and provide helpful suggestions and information.
- Review the assistant's response in the chat history and follow the provided guidance to aid your reverse engineering process.
- Continue the conversation with the assistant as needed, refining your queries and exploring different aspects of the binary analysis.

## Acknowledgments
The system prompt used in this plugin was inspired by the AutoGPT project.
The query functions were adapted from the Gepetto IDA Pro plugin.

## License
This project is licensed under the MIT License.
