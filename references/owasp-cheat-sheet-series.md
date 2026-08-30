# OWASP Cheat Sheet Series (full catalog)

This is the complete OWASP Cheat Sheet Series, 120 sheets, each a practical, actionable guide for a specific vulnerability class or technology. Use this for a direct topic/keyword match against a specific finding: a JWT finding matches the JSON Web Token Cheat Sheet directly, an SSRF finding matches Server-Side Request Forgery Prevention directly, a hardcoded secret matches Secrets Management directly. No routing through a category required.

This is a different file from `owasp-top10-cheatsheet-map.md`. That one is a narrow, 10-row lookup keyed to the OWASP **Web Application** Top 10:2025 categories specifically, used only by `dungeon-crawl-threat-map` to tag a STRIDE threat with a Top 10 category. This file is the complete series, meant for any skill that needs to find the single most relevant remediation guide for a specific vulnerability, not a category.

Cite a sheet by name. Don't guess a URL you're not confident of, the reader can search `cheatsheetseries.owasp.org` for the name directly, the URLs below follow a consistent slug pattern (`Title_With_Underscores_Cheat_Sheet.html`) but aren't guaranteed byte-exact for every entry.

Three sheets are formally deprecated, marked `[DEPRECATED]` below. They're kept in this list rather than removed, their URLs are still live and still get linked from elsewhere.

## A

- Abuse Case - Reviewers have identified that abuse cases are rarely used in practice. - https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html
- Access Control [DEPRECATED] - The Access Control cheatsheet has been deprecated. - https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
- AI Agent Security - AI agents are autonomous systems powered by Large Language Models (LLMs) that can reason, plan, use tools, maintain memory, and take actions to accomplish goals. - https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- AJAX Security - This document will provide a starting point for AJAX security and will hopefully be updated and expanded reasonably often to provide more detailed information about specific frameworks and technologies. - https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html
- AML Sanctions AI Agent Payments - AI agents are initiating regulated financial transactions in production. - https://cheatsheetseries.owasp.org/cheatsheets/AML_Sanctions_AI_Agent_Payments_Cheat_Sheet.html
- Attack Surface Analysis - This article describes a simple and pragmatic way of doing Attack Surface Analysis and managing an application's Attack Surface. - https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html
- Authentication - The primary function of a User ID is to uniquely identify a user within a system. - https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- Authorization - Authorization may be defined as "the process of verifying that a requested action or service is approved for a specific entity" (NIST). - https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- Authorization Regression Testing - Authorization implementation is rarely static. - https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html
- Authorization Testing Automation - To deal with this problem, we recommend that developers automate the evaluation of the authorizations and perform a test when a new release is created. - https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html
- Automotive Security - This document outlines common security vulnerabilities found in automotive security and provides examples of how attackers can exploit these vulnerabilities. - https://cheatsheetseries.owasp.org/cheatsheets/Automotive_Security_Cheat_Sheet.html

## B

- Bean Validation - This article is focused on providing clear, simple, actionable guidance for providing Java Bean Validation security functionality in your applications. - https://cheatsheetseries.owasp.org/cheatsheets/Bean_Validation_Cheat_Sheet.html
- Bot Management and Anti-Automation - Modern web applications face a continuous stream of automated traffic that is not a Distributed Denial of Service event but is still abusive: credential stuffing, content scraping, inventory hoarding (scalping), fake account creation, gift-card enumeration, card testing, fake reviews, click fraud, and more. - https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html
- Browser Extension Vulnerabilities - Browser extensions sometimes request more permissions than they actually need. - https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html
- Business Logic Security - Business logic vulnerabilities are flaws in the way an application implements its intended workflow. - https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html

## C

- C-Based Toolchain Hardening - C-Based Toolchain Hardening is a treatment of project settings that will help you deliver reliable and secure code when using C, C++ and Objective C languages in a number of development environments. - https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html
- Choosing and Using Security Questions - If you are curious, please have a look at this study by Microsoft Research in 2009 and this study performed at Google in 2015. - https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html
- CI CD Security - CI/CD pipelines and processes facilitate efficient, repeatable software builds and deployments; as such, they occupy an important role in the modern SDLC. - https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html
- Clickjacking Defense - This cheat sheet is intended to provide guidance for developers on how to defend against Clickjacking, also known as UI redress attacks. - https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- Content Security Policy - This article brings forth a way to integrate the defense in depth concept to the client-side of web applications. - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- Cookie Theft Mitigation - With the spread of 2FA and Passkey, the login process has become more robust, and even if an attacker steals only the password, it has become difficult to do a spoofing attack. - https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html
- Credential Stuffing Prevention - This cheatsheet covers defenses against two common types of authentication-related attacks: credential stuffing and password spraying. - https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- Cross Site Scripting Prevention - This cheat sheet helps developers prevent XSS vulnerabilities. - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- Cross-Site Request Forgery Prevention - A Cross-Site Request Forgery (CSRF) attack occurs when a malicious web site, email, blog, instant message, or program tricks an authenticated user's web browser into performing an unwanted action on a trusted site. - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- Cryptographic Storage - This article provides a simple model to follow when implementing solutions to protect data at rest. - https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

## D

- Database Security - This cheat sheet provides guidance for securely configuring SQL databases such as MySQL, PostgreSQL, MariaDB, and Microsoft SQL Server. - https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- Denial of Service - This cheat sheet describes a methodology for handling denial of service (DoS) attacks on different layers. - https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- Dependency Graph SBOM - Modern software relies on hundreds of third-party components. - https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html
- Deserialization - This article is focused on providing clear, actionable guidance for safely deserializing untrusted data in your applications. - https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- Django REST Framework - This cheat sheet provides Django REST Framework security advice for developers. - https://cheatsheetseries.owasp.org/cheatsheets/Django_REST_Framework_Cheat_Sheet.html
- Django Security - The Django framework is a powerful Python web framework, and it comes with built-in security features that can be used out-of-the-box to prevent common web vulnerabilities. - https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
- Docker Security - Docker is the most popular containerization technology. - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- DOM based XSS Prevention - When looking at XSS (Cross-Site Scripting), there are three generally recognized forms of XSS. - https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- DOM Clobbering Prevention - DOM Clobbering is a type of code-reuse, HTML-only injection attack, where attackers confuse a web application by injecting HTML elements whose id or name attribute matches the name of security-sensitive variables or browser APIs. - https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html
- DotNet Security - This page intends to provide quick basic .NET security tips for developers. - https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html
- Drone Security - Drone security is crucial due to their widespread adoption in industries such as military, construction, and community services. - https://cheatsheetseries.owasp.org/cheatsheets/Drone_Security_Cheat_Sheet.html

## E

- Email Validation and Verification - Email addresses are widely used as primary identifiers in authentication and account recovery workflows. - https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html
- Error Handling - Error handling is a part of the overall security of an application. - https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

## F

- File Upload - File upload is becoming a more and more essential part of any application, where the user is able to upload their photo, their CV, or a video showcasing a project they are working on. - https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- Forgot Password - In order to implement a proper user management system, systems integrate a Forgot Password service that allows the user to request a password reset. - https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html

## G

- GitHub Actions Security - This cheat sheet provides guidance on securing GitHub Actions workflows, primarily for public GitHub repositories. - https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html
- GraphQL - GraphQL is an open source query language originally developed by Facebook that can be used to build APIs as an alternative to REST and SOAP. - https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- gRPC Security - gRPC (gRPC Remote Procedure Call) is a high-performance, language-neutral RPC framework that uses HTTP/2 for transport and Protocol Buffers for serialization. - https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html

## H

- HTML5 Security - The following cheat sheet serves as a guide for implementing HTML 5 in a secure fashion. - https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- HTTP Headers - HTTP Headers are a great booster for web security with easy implementation. - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- HTTP Strict Transport Security - HTTP Strict Transport Security (also named HSTS) is an opt-in security enhancement that is specified by a web application through the use of a special response header. - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html

## I

- Infrastructure as Code Security - Guidance for securing Infrastructure as Code (Terraform, CloudFormation, and similar) templates and pipelines. - https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html
- Injection Prevention - This article is focused on providing clear, simple, actionable guidance for preventing the entire category of Injection flaws in your applications. - https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- Injection Prevention in Java - This information has been moved to the dedicated Java Security CheatSheet. - https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html
- Input Validation - This article is focused on providing clear, simple, actionable guidance for providing Input Validation security functionality in your applications. - https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- Insecure Direct Object Reference Prevention - Insecure Direct Object Reference (IDOR) is a vulnerability that arises when attackers can access or modify objects by manipulating identifiers used in a web application's URLs or parameters. - https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

## J

- JAAS - The process of verifying the identity of a user or another system is authentication. - https://cheatsheetseries.owasp.org/cheatsheets/JAAS_Cheat_Sheet.html
- Java Security - This section aims to provide tips to handle Injection in Java application code. - https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html
- JSON Web Token - This cheat sheet provides tips to prevent common security issues when using JSON Web Tokens (JWT). - https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html

## K

- Key Management - This Key Management Cheat Sheet provides developers with guidance for implementation of cryptographic key management within an application in a secure manner. - https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- Kubernetes Security - This cheat sheet provides a starting point for securing a Kubernetes cluster. - https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html

## L

- Laravel - This Cheatsheet intends to provide security tips to developers building Laravel applications. - https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html
- LDAP Injection Prevention - The Lightweight Directory Access Protocol (LDAP) allows an application to remotely perform operations such as searching and modifying records. - https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- Legacy Application Management - Legacy applications are applications that are recognized as being outdated but remain in active use by an organization. - https://cheatsheetseries.owasp.org/cheatsheets/Legacy_Application_Management_Cheat_Sheet.html
- LLM Prompt Injection Prevention - Prompt injection is a vulnerability in Large Language Model (LLM) applications that allows attackers to manipulate the model's behavior by injecting malicious input that changes its intended output. - https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- Logging - This cheat sheet is focused on providing developers with concentrated guidance on building application logging mechanisms, especially related to security logging. - https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- Logging Vocabulary - This document proposes a standard vocabulary for logging security events. - https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html

## M

- Mass Assignment - Software frameworks sometimes allow developers to automatically bind HTTP request parameters into program code variables or objects to make using that framework easier on developers. - https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- MCP Security - The Model Context Protocol (MCP), introduced by Anthropic in November 2024, standardizes how AI applications (LLM clients) connect to external tools, data sources, and services. - https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- Microservices based Security Arch Doc - The microservice architecture is being increasingly used for designing and implementing application systems in both cloud-based and on-premise infrastructures. - https://cheatsheetseries.owasp.org/cheatsheets/Microservices_based_Security_Arch_Doc_Cheat_Sheet.html
- Microservices Security - The microservice architecture is being increasingly used for designing and implementing application systems in both cloud-based and on-premise infrastructures, high-scale applications and services. - https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html
- Mobile Application Security - Mobile application development presents certain security challenges. - https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html
- Multi Tenant Security - Multi-tenant applications serve multiple customers (tenants) from a shared infrastructure, codebase, and often shared databases. - https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html
- Multifactor Authentication - Multifactor Authentication (MFA) or Two-Factor Authentication (2FA) is when a user is required to present more than one type of evidence in order to authenticate on a system. - https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

## N

- Network Segmentation - Network segmentation is the core of multi-layer defense in depth for modern services. - https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html
- NodeJS Docker - The following cheatsheet provides production-grade guidelines for building optimized and secure Node.js Docker images. - https://cheatsheetseries.owasp.org/cheatsheets/NodeJS_Docker_Cheat_Sheet.html
- Nodejs Security - This cheat sheet lists actions developers can take to develop secure Node.js applications. - https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
- NoSQL Security - NoSQL databases (MongoDB, CouchDB, Cassandra etc.) power many modern applications with flexible schemas and horizontal scale. - https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html
- NPM Security - The following cheatsheet covers several npm security best practices and productivity tips, useful for JavaScript and Node.js developers. - https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html

## O

- OAuth2 - This cheatsheet describes the best current security practices for OAuth 2.0 as derived from its RFC. - https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- OS Command Injection Defense - Command injection (or OS Command Injection) is a type of injection where software that constructs a system command using externally influenced input does not correctly neutralize the input from special elements that can modify the initially intended command. - https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

## P

- Password Storage - This cheat sheet advises you on the proper methods for storing passwords for authentication. - https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- PHP Configuration - This page is meant to help those configuring PHP and the web server it is running on to be very secure. - https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html
- Pinning - The Pinning Cheat Sheet is a technical guide to implementing certificate and public key pinning. - https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html
- Prototype Pollution Prevention - Prototype Pollution is a critical vulnerability that can allow attackers to manipulate an application's JavaScript objects and properties, leading to serious security issues such as unauthorized access to data, privilege escalation, and even remote code execution. - https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

## Q

- Query Parameterization - SQL Injection is one of the most dangerous web vulnerabilities. - https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

## R

- RAG Security - Retrieval Augmented Generation (RAG) is now standard architecture for enterprise AI applications. - https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html
- REST Assessment - Web Services are an implementation of web technology used for machine to machine communication. - https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html
- REST Security - REST (or REpresentational State Transfer) is an architectural style first described in Roy Fielding's Ph.D. dissertation. - https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- Ruby on Rails - This Cheatsheet intends to provide quick basic Ruby on Rails security tips for developers. - https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html

## S

- SAML Security - The Security Assertion Markup Language (SAML) is an open standard for exchanging authorization and authentication information. - https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- Secrets Management - Secrets are being used everywhere nowadays, especially with the popularity of the DevOps movement. - https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- Secure AI Model Ops - This cheat sheet provides practical security guidance for operating and deploying AI/ML systems, including traditional machine learning models and large language models (LLMs). - https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html
- Secure Cloud Architecture - This cheat sheet will discuss common and necessary security patterns to follow when creating and reviewing cloud architectures. - https://cheatsheetseries.owasp.org/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.html
- Secure Code Review - This cheat sheet provides practical guidance for conducting effective manual security code reviews, with emphasis on both baseline and incremental review methodologies. - https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html
- Secure Coding with AI - AI coding tools have moved beyond code suggestion. - https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_with_AI_Cheat_Sheet.html
- Secure Product Design - The purpose of Secure Product Design is to ensure that all products meet or exceed the security requirements laid down by the organization as part of the development lifecycle. - https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html
- Securing Cascading Style Sheets - The goal of this CSS (not XSS, but Cascading Style Sheet) Cheat Sheet is to inform programmers, testers, security analysts, and front-end developers how to achieve better security when authoring CSS. - https://cheatsheetseries.owasp.org/cheatsheets/Securing_Cascading_Style_Sheets_Cheat_Sheet.html
- Security Terminology - This cheat sheet provides clear definitions and distinctions for security terminology that is often confused, even by experienced developers. - https://cheatsheetseries.owasp.org/cheatsheets/Security_Terminology_Cheat_Sheet.html
- Server Side Request Forgery Prevention - The objective of the cheat sheet is to provide advice regarding the protection against Server Side Request Forgery (SSRF) attacks. - https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Serverless FaaS Security - Serverless computing (Functions as a Service, FaaS) platforms such as AWS Lambda, Azure Functions, and Google Cloud Functions simplify application development and scaling. - https://cheatsheetseries.owasp.org/cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.html
- Session Management - A web session is a sequence of network HTTP request and response transactions associated with the same user. - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Software Supply Chain Security - No piece of software is developed in a vacuum; regardless of the technologies used to develop it, software is embedded in a Software Supply Chain (SSC). - https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html
- SQL Injection Prevention - This cheat sheet will help you prevent SQL injection flaws in your applications. - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- Subdomain Takeover Prevention - Subdomain takeover is a vulnerability that occurs when a DNS record (typically a CNAME) points to a cloud resource or third-party service that has been deprovisioned or no longer exists. - https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html
- Symfony - This cheat sheet aims to provide developers with security tips when building applications using the Symfony framework. - https://cheatsheetseries.owasp.org/cheatsheets/Symfony_Cheat_Sheet.html

## T

- Third Party Javascript Management - Tags, aka marketing tags, analytics tags etc., are widely used third-party scripts embedded in web pages. - https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html
- Third Party Payment Gateway Integration - Integrating third-party payment gateways allows businesses to securely outsource payment processing. - https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Payment_Gateway_Integration_Cheat_Sheet.html
- Threat Modeling - Threat modeling is an important concept for modern application developers to understand. - https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- TLS Cipher String [DEPRECATED] - The TLS Cipher String Cheat Sheet has been deprecated. - https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
- Transaction Authorization - This cheat sheet discusses how developers can secure transaction authorizations and prevent them from being bypassed. - https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html
- Transport Layer Protection [DEPRECATED] - The Transport Layer Protection Cheat Sheet has been deprecated. - https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
- Transport Layer Security - This cheat sheet provides guidance on implementing transport layer protection for applications using Transport Layer Security (TLS). - https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html

## U

- Unvalidated Redirects and Forwards - Unvalidated redirects and forwards are possible when a web application accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. - https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- User Privacy Protection - This OWASP Cheat Sheet introduces mitigation methods that web developers may utilize in order to protect their users from a vast array of potential threats and aggressions that might try to undermine their privacy and anonymity. - https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html

## V

- Virtual Patching - The goal with this cheat sheet is to present a concise virtual patching framework that organizations can follow to maximize the timely implementation of mitigation protections. - https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html
- Vulnerability Disclosure - This cheat sheet is intended to provide guidance on the vulnerability disclosure process for both security researchers and organizations. - https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html
- Vulnerable Dependency Management - The objective of the cheat sheet is to provide a proposal of approach regarding the handling of vulnerable third-party dependencies when they are detected. - https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

## W

- Web Service Security - This article is focused on providing guidance for securing web services and preventing web services related attacks. - https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html
- WebSocket Security - WebSockets enable real-time, bidirectional communication between clients and servers, powering applications like chat systems, live trading platforms, and collaborative tools. - https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html

## X

- XML External Entity Prevention - An XML eXternal Entity injection (XXE) is an attack against applications that parse XML input. - https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- XML Security - While the specifications for XML and XML schemas provide you with the tools needed to protect XML applications, they also include multiple security flaws. - https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html
- XS Leaks - This article describes examples of attacks and defenses against cross-site leaks vulnerability (XS Leaks). - https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html
- XSS Filter Evasion - This article is a guide to Cross Site Scripting (XSS) testing for application security professionals. - https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

## Z

- Zero Trust Architecture - This cheat sheet will help you implement Zero Trust Architecture (ZTA) in your organization. - https://cheatsheetseries.owasp.org/cheatsheets/Zero_Trust_Architecture_Cheat_Sheet.html

## Notes on accuracy

- Titles, paths, and descriptions are pulled from the master branch of the OWASP CheatSheetSeries GitHub repository's `Index.md`. Descriptions are each sheet's own opening sentence, not a summary written for this file.
- 120 entries total, matching the live index at https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/Index.md at the time this catalog was compiled.
- Deprecated sheets are retained with a `[DEPRECATED]` marker rather than removed, since their URLs are still live and still get linked elsewhere.
