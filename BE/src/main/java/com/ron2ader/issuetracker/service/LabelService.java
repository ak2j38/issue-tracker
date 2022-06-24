package com.ron2ader.issuetracker.service;

import com.ron2ader.issuetracker.controller.labeldto.LabelRequest;
import com.ron2ader.issuetracker.controller.labeldto.LabelResponse;
import com.ron2ader.issuetracker.controller.labeldto.LabelsResponse;
import com.ron2ader.issuetracker.domain.label.Label;
import com.ron2ader.issuetracker.domain.label.LabelRepository;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class LabelService {

    private final LabelRepository labelRepository;

    @Transactional
    public LabelResponse save(String title, String color, String description) {
        Label savedLabel = labelRepository.save(
            Label.of(title, color, description));

        return LabelResponse.from(savedLabel);
    }

    @Transactional(readOnly = true)
    public List<LabelsResponse> findAll() {
        List<Label> labels = labelRepository.findAll();

        return labels.stream()
            .map(LabelsResponse::from)
            .collect(Collectors.toUnmodifiableList());
    }

    @Transactional
    public LabelResponse update(Long id, String title, String color, String description) {
        Label findLabel = labelRepository.findById(id).orElseThrow(NoSuchElementException::new);
        findLabel.update(title, color, description);

        return LabelResponse.from(findLabel);
    }

    @Transactional
    public void deleteById(Long id) {
        labelRepository.findById(id).orElseThrow(NoSuchElementException::new);

        labelRepository.deleteById(id);
    }
}
