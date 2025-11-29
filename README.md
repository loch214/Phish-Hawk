# Phish-Hawk 🦅 (V1)

This is a simple email analysis tool I built to get better at software engineering and understand a bit about cybersecurity. I wanted to create a tool that could look at a suspicious email file or text and try to figure out if it's a phishing attempt.

It's a full-stack application with a Java Spring Boot backend and a simple HTML/JS frontend.

## What It Does (The V1 Features)
*   **Checks Technical Headers:** It looks at the hidden sender information (like `From` and `Return-Path`) to see if they match. If they don't, it's a sign the sender might be faking their address.
*   **Looks for Sketchy Links:** It pulls out all the links from the email. If the email claims to be from `my-bank.com` but the links go to `totally-not-a-scam.net`, it flags it.
*   **Reads Inside PDFs:** Using a library called Apache PDFBox, it can open up PDF attachments and read the text inside to scan for threats.
*   **Scans for Keywords:** It has a basic list of high-risk "scam" words (like "lottery winner," "account suspended," etc.) and flags the email if it finds them.

## The Big Limitation of V1
After building this, I realized a major weakness. Because the tool just uses a fixed list of keywords, it's not very smart. I call this a "Rule-Based" system.

The problem is that it has no understanding of **context**.

I noticed that a lot of perfectly legitimate emails also use words like "account," "update payment," or "unsubscribe." A simple keyword list would flag tons of normal emails as suspicious, which makes the tool unreliable. It creates too many "false positives."

## The Plan for V2: The AI Upgrade
That's why I decided the next step for this project is to make it smarter using a simple AI model.

Instead of just checking for keywords, the plan is to train a basic NLP (Natural Language Processing) model on thousands of real spam and legitimate emails. The AI would learn the *patterns*, sentence structures, and the *context* that make an email feel "phishy," not just the words themselves.

This V1 is the foundation. V2 will be about replacing the simple keyword list with a trained AI model to get much more accurate results and make the tool genuinely useful.
