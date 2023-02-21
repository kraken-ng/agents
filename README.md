# Agents

This repository contains the templates for the different agents of [Kraken](https://github.com/kraken-ng/Kraken).

Kraken agents are pieces of code whose function is to execute the received modules using an **Executor**. The executors vary depending on the technology and environment. An example of executor could be: in a PHP web application, the `eval()` function (which allows executing PHP code in raw).

The important and essential point of Kraken agents is that **they allow to execute modules instead of system commands** (avoiding the traditional way of web post-exploitation).

## Types of Agents

Currently, there are 2 types of agents in Kraken:

- [Standard Agents](standard): traditional web implants that receive modules with arguments, which are executed, and a response is returned.
- [Command and Control Agents](c2): version of a web implant that loads the modules received in "memory" (persisting the information using session variables) as a Command and Control would do. It allows loading and unloading modules, as well as invoking them (only available in PHP at now).

> Important: C2 agents, with increasing complexity, are more prone to failures. It is recommended to use the Standard agents if is possible.

## Agent Versions

Three versions of Kraken agents are available, corresponding to the programming languages most commonly used in web services: **PHP, Java (JSP) and .NET (ASPX)**.

## Agent Executors

At the moment, the executors used by Kraken agents are very simple but allow a correct operation of the modules. They are represented in the following table:

|    PHP   |  JAVA (JSP)   |     .NET (ASPX)      |
|:--------:|:-------------:|:--------------------:|
| `eval()` | `ClassLoader` | `CSharpCodeProvider` |

There are many more executors that can be used. But, for now, these 3 are standard in most web platforms and we have been able to build the tool according to them.

## Contribute

The contribution with Kraken custom agents will be detailed in the future.
