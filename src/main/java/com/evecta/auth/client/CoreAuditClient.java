package com.evecta.auth.client;

import com.evecta.auth.dto.core.AuditLogRequestDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "core-service", url = "${core.service.url}")
public interface CoreAuditClient {

  @PostMapping("/internal/audit")
  void registrarLog(@RequestBody AuditLogRequestDTO request);
}
