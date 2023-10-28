package com.security.test.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Data
@Builder
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GlobalExceptionResponse {

    private String httpMethod;

    private String requestUri;

    private Integer statusCode;

    private String statusText;

    private String errorTimestamp;

    @JsonProperty(value = "detailedErrors")
    private List<ExceptionResponse> exceptions;
}
