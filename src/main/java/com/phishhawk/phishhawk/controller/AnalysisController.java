package com.phishhawk.phishhawk.controller;

import org.springframework.web.bind.annotation.RequestBody;
import com.phishhawk.phishhawk.dto.AnalysisResult;
import com.phishhawk.phishhawk.service.EmailAnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/analyze")
public class AnalysisController {

    @Autowired
    private EmailAnalysisService emailAnalysisService;

    @PostMapping("/email-content")
    public AnalysisResult analyzeEmailContent(@RequestBody String emailContent) {
        return emailAnalysisService.analyzeEmailContent(emailContent);
    }

    @PostMapping("/email")
    public AnalysisResult analyzeEmailFile(@RequestParam("emailFile") MultipartFile file) {
        return emailAnalysisService.analyzeEmail(file);
    }
}