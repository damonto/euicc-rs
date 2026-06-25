use crate::rsp::{ExecutionStatus, StatusCodeData};
use crate::{EuiccError, Result, es9p, es11};

pub(super) trait RspExecutionStatus {
    fn execution_status(&self) -> Option<ExecutionStatus>;
}

impl RspExecutionStatus for es9p::InitiateAuthenticationResponse {
    fn execution_status(&self) -> Option<ExecutionStatus> {
        self.execution_status().cloned()
    }
}

impl RspExecutionStatus for es9p::AuthenticateClientResponse {
    fn execution_status(&self) -> Option<ExecutionStatus> {
        Some(
            self.execution_status()
                .cloned()
                .unwrap_or_else(|| ExecutionStatus {
                    status: "Failed".to_owned(),
                    status_code_data: Some(missing_execution_status_data()),
                }),
        )
    }
}

impl RspExecutionStatus for es9p::GetBoundProfilePackageResponse {
    fn execution_status(&self) -> Option<ExecutionStatus> {
        self.execution_status().cloned()
    }
}

impl RspExecutionStatus for es9p::HandleNotificationResponse {
    fn execution_status(&self) -> Option<ExecutionStatus> {
        self.execution_status()
    }
}

impl RspExecutionStatus for es9p::CancelSessionResponse {
    fn execution_status(&self) -> Option<ExecutionStatus> {
        self.execution_status().cloned()
    }
}

impl RspExecutionStatus for es11::AuthenticateClientResponse {
    fn execution_status(&self) -> Option<ExecutionStatus> {
        self.execution_status().cloned()
    }
}
pub(super) fn check_rsp_status(response: &impl RspExecutionStatus) -> Result<()> {
    let Some(status) = response.execution_status() else {
        return Err(EuiccError::RspStatus(missing_execution_status_data()));
    };
    if status.executed_success() {
        return Ok(());
    }
    Err(EuiccError::RspStatus(
        status.status_code_data.unwrap_or_else(|| StatusCodeData {
            subject_code: String::new(),
            reason_code: String::new(),
            message: Some(status.status),
        }),
    ))
}

fn missing_execution_status_data() -> StatusCodeData {
    StatusCodeData {
        subject_code: String::new(),
        reason_code: String::new(),
        message: Some("missing function execution status".to_owned()),
    }
}
