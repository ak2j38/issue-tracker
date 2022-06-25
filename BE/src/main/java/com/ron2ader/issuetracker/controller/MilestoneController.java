package com.ron2ader.issuetracker.controller;

import com.ron2ader.issuetracker.controller.milestonedto.MilestoneRequest;
import com.ron2ader.issuetracker.controller.milestonedto.MilestoneResponse;
import com.ron2ader.issuetracker.service.MilestoneService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class MilestoneController {

    private final MilestoneService milestoneService;

    @GetMapping("/milestones")
    public List<MilestoneResponse> getMilestones() {
        return milestoneService.findAll();
    }

    @PostMapping("/milestones")
    public MilestoneResponse register(MilestoneRequest milestoneRequest) {
        return milestoneService.save(milestoneRequest.getTitle(),
                milestoneRequest.getDescription(),
                milestoneRequest.getEndDate());
    }

    @PostMapping("/milestones/{id}")
    public MilestoneResponse update(@PathVariable Long id, MilestoneRequest milestoneRequest) {
        return milestoneService.update(id, milestoneRequest.getTitle(),
                milestoneRequest.getDescription(),
                milestoneRequest.getEndDate());
    }

    @DeleteMapping("/milestones/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id) {
        milestoneService.delete(id);
    }

}
