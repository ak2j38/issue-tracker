package com.ron2ader.issuetracker.service;

import com.ron2ader.issuetracker.controller.milestonedto.MilestoneRequest;
import com.ron2ader.issuetracker.controller.milestonedto.MilestoneResponse;
import com.ron2ader.issuetracker.domain.milestone.Milestone;
import com.ron2ader.issuetracker.domain.milestone.MilestoneRepository;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MilestoneService {

    private final MilestoneRepository milestoneRepository;

    @Transactional(readOnly = true)
    public List<MilestoneResponse> findAll() {
        List<Milestone> milestones = milestoneRepository.findAll();

        List<MilestoneResponse> milestoneResponses = new ArrayList<>();
        for (Milestone milestone : milestones) {
            Long openCount = milestone.issueCountByOpenStatus(true);
            Long closeCount = milestone.issueCountByOpenStatus(false);
            milestoneResponses.add(MilestoneResponse.of(milestone.getId(), milestone.getTitle(),
                milestone.getDescription(), milestone.getEndDate(), openCount, closeCount));
        }

        return milestoneResponses;
    }

    @Transactional
    public MilestoneResponse save(String title, String description, LocalDate endDate) {
        Milestone saveMilestone = milestoneRepository.save(
            Milestone.of(title, description, endDate));

        return MilestoneResponse.fromForRegister(saveMilestone);
    }

    @Transactional
    public MilestoneResponse update(Long id, String title, String description, LocalDate endDate) {
        Milestone findMilestone = milestoneRepository.findById(id).orElseThrow(NoSuchElementException::new);
        findMilestone.update(title, description, endDate);

        return MilestoneResponse.of(findMilestone.getId(), findMilestone.getTitle(), findMilestone.getDescription(),
            findMilestone.getEndDate(), findMilestone.issueCountByOpenStatus(true),
            findMilestone.issueCountByOpenStatus(false));
    }

    @Transactional
    public void delete(Long id) {
        Milestone deleteMilestone = milestoneRepository.findById(id).orElseThrow(NoSuchElementException::new);

        milestoneRepository.delete(deleteMilestone);
    }
}
