package com.phishhawk.phishhawk.dto;

import lombok.Data;
import java.util.List; // <-- IMPORTANT: Import List

@Data
public class AnalysisResult {

    private String fromHeader;
    private String returnPathHeader;
    private String receivedHeader;

    private boolean suspicious;
    private String analysisSummary;

    // --- NEW FIELD ---
    // This will hold all the links we find in the email body.
    private List<String> foundUrls;
}