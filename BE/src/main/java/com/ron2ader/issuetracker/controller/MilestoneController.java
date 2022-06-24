package com.ron2ader.issuetracker.controller;

import com.ron2ader.issuetracker.controller.milestonedto.MilestoneRequest;
import com.ron2ader.issuetracker.controller.milestonedto.MilestoneResponse;
import com.ron2ader.issuetracker.service.MilestoneService;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MilestoneController {

    private final MilestoneService milestoneService;

    @GetMapping("/milestones")
    public List<MilestoneResponse> getMilestones() {
        return milestoneService.findAll();
    }

    @PostMapping("/milestones")
    public MilestoneResponse register(String title, String description, LocalDate endDate) {
        return milestoneService.save(title, description, endDate);
    }

    @PostMapping("/milestones/{id}")
    public MilestoneResponse update(@PathVariable Long id, String title, String description, LocalDate endDate) {
        return milestoneService.update(id, title, description, endDate);
    }

    @DeleteMapping("/milestones/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        milestoneService.delete(id);
        return ResponseEntity.noContent().build();
    }

}
