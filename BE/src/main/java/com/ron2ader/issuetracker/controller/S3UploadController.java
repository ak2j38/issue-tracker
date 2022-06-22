package com.ron2ader.issuetracker.controller;

import com.ron2ader.issuetracker.service.S3UploadService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequiredArgsConstructor
public class S3UploadController {

    private final S3UploadService s3uploadService;

    @PostMapping("/images/upload")
    public String upload(@RequestPart("file") MultipartFile multipartFile) {
        return s3uploadService.uploadPublic(multipartFile);
    }

}
