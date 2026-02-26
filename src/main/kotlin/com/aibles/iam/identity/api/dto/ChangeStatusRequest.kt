package com.aibles.iam.identity.api.dto

import com.aibles.iam.identity.domain.user.UserStatus
import jakarta.validation.constraints.NotNull

data class ChangeStatusRequest(
    @field:NotNull val status: UserStatus,
)
