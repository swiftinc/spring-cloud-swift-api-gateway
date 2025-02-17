package com.swift.apidev.swiftgateway;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = RANDOM_PORT)
public class SwiftApiGatewayIT {

    @Autowired
    WebTestClient webClient;

    @Test
    public void bnkabebbPreValidationTest() {
        prevalTest("bnkabebb");
    }

    @Test
    public void bnkbebbPreValidationTest() {
        prevalTest("bnkbbebb");
    }

    @Test
    public void bnkbebbGpiTrackerTest() {
        webClient
                .get()
                .uri("/gpi-tracker/97ed4827-7b6f-4491-a06f-b548d5a7512d")
                .header("X-Consumer-Custom-ID", "bnkbbebb")
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    public void bnkbebbStopAndRecallTest() {
        String body = """
                {
                    "from": "GPIBBICXXXX",
                    "service_level": "G002",
                    "case_identification": "case123",
                    "original_message_name_identification": "pacs.008",
                    "original_instruction_identification": "ABC123",
                    "cancellation_reason_information": "DUPL",
                    "indemnity_agreement": "INDM",
                    "creator": "GPIABICXXXX"
                }
                """;

        webClient
                .put()
                .uri("/gpi-tracker-gsrp/97ed4827-7b6f-4491-a06f-b548d5a7512d")
                .header("X-Consumer-Custom-ID", "bnkbbebb")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isOk();
    }

    private void prevalTest(String bic) {
        String body = """
                {
                    "correlation_identifier": "112211221122",
                    "context": "BENR",
                    "uetr": "97ed4827-7b6f-4491-a06f-b548d5a7512d",
                    "creditor_account": "7892368367",
                    "creditor_name": "DEF Electronics",
                    "creditor_agent": {
                        "bicfi": "AAAAUS2L"
                    },
                    "creditor_agent_branch_identification": "NY8877888"
                }
                """;

        webClient
                .post()
                .uri("/swift-preval/v2/accounts/verification")
                .header("X-Consumer-Custom-ID", bic)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isOk();
    }
}
