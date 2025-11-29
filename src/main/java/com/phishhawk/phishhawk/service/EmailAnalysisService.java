package com.phishhawk.phishhawk.service;

import com.phishhawk.phishhawk.dto.AnalysisResult;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class EmailAnalysisService {

    // Regex to find raw URLs
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?:(?:https?|ftp)://|www\\.|ftp\\.)(?:\\([-A-Z0-9+&@#/%=~_|$?!:,.]*\\)|[-A-Z0-9+&@#/%=~_|$?!:,.])*(?:\\([-A-Z0-9+&@#/%=~_|$?!:,.]*\\)|[A-Z0-9+&@#/%=~_|$])",
            Pattern.CASE_INSENSITIVE
    );

    // Common Scam Phrases
    private static final List<String> SCAM_PHRASES = Arrays.asList(
            "free spins", "claim your bonus", "no deposit needed", "jackpot", "winner",
            "lottery", "click here", "verify your account", "suspended", "urgent action",
            "account locked", "update payment", "social security", "credit card",
            "bank account", "limited time", "act now", "promo code", "unsubscribe",
            "cloud storage", "payment method has expired", "subscription id"
    );

    // Suspicious Keywords in Sender Domain
    private static final List<String> SUSPICIOUS_DOMAIN_KEYWORDS = Arrays.asList(
            "login", "secure", "account", "verify", "alert", "support", "service", "bank", "invoice"
    );

    // NEW: Cloud Storage Domains (Hackers use these to bypass filters)
    private static final List<String> SUSPICIOUS_CLOUD_DOMAINS = Arrays.asList(
            "googleapis.com", "firebasestorage.com", "amazonaws.com", "blob.core.windows.net",
            "dropbox.com", "drive.google.com", "docs.google.com", "herokuapp.com"
    );

    public AnalysisResult analyzeEmail(MultipartFile emailFile) {
        if (emailFile == null || emailFile.isEmpty()) return createErrorResult("Error: No file was provided.");

        try {
            String content = "";
            String filename = emailFile.getOriginalFilename();

            // --- PDF PARSING LOGIC ---
            if (filename != null && filename.toLowerCase().endsWith(".pdf")) {
                try (PDDocument document = PDDocument.load(emailFile.getInputStream())) {
                    PDFTextStripper stripper = new PDFTextStripper();
                    content = stripper.getText(document);
                }
            } else {
                // Default Text Parsing
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(emailFile.getInputStream()))) {
                    content = reader.lines().collect(Collectors.joining("\n"));
                }
            }

            return analyzeEmailContent(content);

        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResult("Critical Error processing file: " + e.getMessage());
        }
    }

    public AnalysisResult analyzeEmailContent(String emailContent) {
        if (emailContent == null || emailContent.trim().isEmpty()) return createErrorResult("Error: No content provided.");

        AnalysisResult result = new AnalysisResult();
        result.setFoundUrls(new ArrayList<>());

        try {
            // 1. Basic Extraction
            String fromHeader = "Not Found";
            String returnPathHeader = "Not Found";
            for (String line : emailContent.split("\n")) {
                String lowerLine = line.toLowerCase();
                if (lowerLine.startsWith("from:")) fromHeader = line.substring(5).trim();
                if (lowerLine.startsWith("return-path:")) returnPathHeader = line.substring(12).trim();
            }
            result.setFromHeader(fromHeader);
            result.setReturnPathHeader(returnPathHeader);

            // 2. Link Extraction
            Document doc = Jsoup.parse(emailContent);
            Elements links = doc.select("a[href]");
            for (org.jsoup.nodes.Element link : links) result.getFoundUrls().add(link.attr("href"));

            Matcher matcher = URL_PATTERN.matcher(emailContent);
            while (matcher.find()) {
                String foundUrl = matcher.group(0);
                if (!result.getFoundUrls().contains(foundUrl)) result.getFoundUrls().add(foundUrl);
            }

            // 3. Apply Rules
            applySuspicionRules(result, emailContent);

        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResult("Error processing content.");
        }
        return result;
    }

    private void applySuspicionRules(AnalysisResult result, String fullContent) {
        List<String> issues = new ArrayList<>();
        String fromDomain = getDomainFromEmail(result.getFromHeader());
        String returnPathDomain = getDomainFromEmail(result.getReturnPathHeader());

        // Rule 1: Header Spoofing
        if (returnPathDomain != null && fromDomain != null && !fromDomain.equalsIgnoreCase(returnPathDomain)) {
            issues.add("Header spoofing detected. Sender domain does not match origin.");
        }

        // Rule 2: Suspicious Content (NLP Lite)
        String lowerContent = fullContent.toLowerCase();
        List<String> foundPhrases = new ArrayList<>();
        for (String phrase : SCAM_PHRASES) {
            if (lowerContent.contains(phrase)) foundPhrases.add(phrase);
        }
        if (!foundPhrases.isEmpty()) {
            issues.add("Suspicious Content: Found common scam phrases: " + String.join(", ", foundPhrases));
        }

        // Rule 3: Cloud Storage Abuse (NEW) & Domain Checks
        if (!result.getFoundUrls().isEmpty()) {
            for (String url : result.getFoundUrls()) {
                String linkDomain = getDomainFromUrl(url);
                if (linkDomain == null) continue;

                // Check for Cloud Storage Abuse
                for (String cloudDomain : SUSPICIOUS_CLOUD_DOMAINS) {
                    if (linkDomain.contains(cloudDomain)) {
                        issues.add("Suspicious Link Hosting: Link points to a public cloud storage (" + cloudDomain + "). Legitimate services usually do not use public cloud buckets for emails.");
                    }
                }

                // Check for Mismatch
                if (fromDomain != null && !linkDomain.endsWith(fromDomain) && !isCloudDomain(linkDomain)) {
                    // We skip this check if it's a cloud domain, because the cloud rule above covers it
                    issues.add("Link Mismatch: Link to '" + linkDomain + "' does not match sender.");
                }
            }
        }

        // Final Verdict
        if (issues.isEmpty()) {
            result.setSuspicious(false);
            result.setAnalysisSummary("Analysis complete. No obvious threats found.");
        } else {
            result.setSuspicious(true);
            result.setAnalysisSummary(String.join(" | ", issues));
        }
    }

    // Helpers
    private boolean isCloudDomain(String domain) {
        for (String cloud : SUSPICIOUS_CLOUD_DOMAINS) {
            if (domain.contains(cloud)) return true;
        }
        return false;
    }

    private String getDomainFromEmail(String email) {
        if (email == null || !email.contains("@")) return null;
        int atIndex = email.lastIndexOf('@');
        String part = email.substring(atIndex + 1);
        if (part.contains(">")) part = part.substring(0, part.indexOf('>'));
        return part.trim();
    }
    private String getDomainFromUrl(String url) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String domain = uri.getHost();
            return (domain != null && domain.startsWith("www.")) ? domain.substring(4) : domain;
        } catch (Exception e) { return null; }
    }
    private AnalysisResult createErrorResult(String message) {
        AnalysisResult result = new AnalysisResult();
        result.setSuspicious(true);
        result.setAnalysisSummary(message);
        result.setFoundUrls(new ArrayList<>());
        return result;
    }
}