# 🐚 Custom Linux Shell

## 📝 Project Overview

This project is a **custom-built Linux shell** developed in **C**, designed to emulate and extend the functionality of standard Unix shells like Bash. It provides a command-line interface that interprets and executes user commands, handling various shell features and system interactions.

## 🚀 Features Implemented

- **Command Parsing** 🔍  
  Parses user input to identify commands and their arguments.

- **Built-in Commands** 🛠️  
  Implements essential built-in commands such as:
  - `cd`: Change the current working directory.
  - `exit`: Exit the shell session.
  - `help`: Display information about built-in commands.

- **External Command Execution** ⚙️  
  Executes external programs by searching the system's PATH, using system calls like `fork()` and `execvp()`.

- **Pipelining** 🔗  
  Enables the use of pipes (`|`) to connect multiple commands, directing the output of one command as the input to another.

- **Signal Handling** 🚦  
  Handles signals such as `SIGINT` and `SIGTSTP` to manage process interruptions gracefully.

## 🔧 How It Works

1. **Initialization**: The shell initializes necessary data structures and enters a loop to continuously accept user input.

2. **Input Reading**: Reads a line of input from the user.

3. **Parsing**: Tokenizes the input to separate commands, arguments, and operators (like pipes and redirection symbols).

4. **Execution**:
   - If the command is a built-in, it executes the corresponding function.
   - If the command is external, it creates a child process using `fork()` and executes the command using `execvp()`.

5. **Signal Handling**: Captures and handles signals to ensure the shell remains responsive and stable.

6. **Loop Continuation**: After executing the command(s), the shell returns to step 2, awaiting the next user input.

---

Feel free to explore the codebase to understand the implementation details and customize it to fit your specific needs! 😊
