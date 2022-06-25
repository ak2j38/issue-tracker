package com.ron2ader.issuetracker.service;

import com.ron2ader.issuetracker.controller.milestonedto.MilestoneResponse;
import com.ron2ader.issuetracker.domain.milestone.Milestone;
import com.ron2ader.issuetracker.domain.milestone.MilestoneRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MilestoneService {

    private final MilestoneRepository milestoneRepository;

    @Transactional(readOnly = true)
    public List<MilestoneResponse> findAll() {
        List<Milestone> milestones = milestoneRepository.findAll();

        return  milestones.stream().map(MilestoneResponse::from).collect(Collectors.toList());
    }

    @Transactional
    public MilestoneResponse save(String title, String description, LocalDate endDate) {
        Milestone saveMilestone = milestoneRepository.save(Milestone.of(title, description, endDate));

        return MilestoneResponse.from(saveMilestone);
    }

    @Transactional
    public MilestoneResponse update(Long id, String title, String description, LocalDate endDate) {
        Milestone findMilestone = milestoneRepository.findById(id)
                .orElseThrow(NoSuchElementException::new);

        findMilestone.update(title, description, endDate);

        return MilestoneResponse.from(findMilestone);
    }

    @Transactional
    public void delete(Long id) {
        milestoneRepository.deleteById(id);
    }
}
