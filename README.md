# Agents

This repository contains the templates for the different agents of [Kraken](https://github.com/kraken-ng/Kraken).

Kraken agents are pieces of code whose function is to execute the received modules using an **Executor**. The executors vary depending on the technology and environment. An example of executor could be: in a PHP web application, the `eval()` function (which allows executing PHP code in raw).

The important and essential point of Kraken agents is that **they allow to execute code instead of system commands** (avoiding the standard behavior of traditional webshells).

## Types of Agents

Currently, there are 2 types of agents in Kraken:

- [Standard Agents](standard): traditional web implants that receive modules with arguments, which are executed, and a response is returned.
- [Command and Control Agents](c2): version of a web implant that loads the modules received in "memory" (persisting the information using session variables) as a Command and Control would do (example: Reflective DLL). It allows loading and unloading modules, as well as invoking them (only available in PHP at now).

> Important: C2 agents, with increasing complexity, are more prone to failures. It is recommended to use the Standard agents if is possible.

## Agent Versions

Three versions of Kraken agents are available, corresponding to the programming languages most commonly used in web services: **PHP, Java (JSP) and .NET (ASPX)**.

## Agent Executors

At the moment, the executors used by Kraken agents are very simple but allow a correct operation of the modules. They are represented in the following table:

|    PHP   |  JAVA (JSP)   |     .NET (ASPX)      |
|:--------:|:-------------:|:--------------------:|
| `eval()` | `ClassLoader` | `CSharpCodeProvider` |
| `create_function()` | - |  `Assembly.Load()` |
| `include() / require()` | - | `System.Reflection.Emit` |

There are more executors that can be used. But, there are 3 default agents that work in most the web platforms and we have been able to build the tool according to them:
- In PHP: `eval()`
- In Java: `ClassLoader`
- In .NET: `CSharpCodeProvider`

For an agent to be able to load the modules through its executor, it is necessary that the client packages the modules in the correct way. This packaging process is carried out by the "compilers" (in the client) and it is essential for the execution to be correct. Each executor (of the agent) has a series of compilers with which it can be used.

The following table contains the relationship between the executors and compilers that must be used in order for the modules to be loaded correctly:

| Language | Executor | Compiler |
|:--------:|:--------:|:--------:|
| PHP | `eval()` | raw |
| PHP | `create_function()` | raw |
| PHP | `include() / require()` | raw |
| Java | `ClassLoader` | container |
| .NET | `CSharpCodeProvider` | raw |
| .NET | `Assembly.Load()` | csc, precompiled |
| .NET | `System.Reflection.Emit` | csc, precompiled |

## Contribute

You can find the contribution guide to create new Kraken agents in the [Wiki](https://github.com/kraken-ng/Kraken/wiki/Contribute#agents).
