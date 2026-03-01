package com.aibles.iam.identity.api

import com.aibles.iam.identity.api.dto.ChangeStatusRequest
import com.aibles.iam.identity.api.dto.CreateUserRequest
import com.aibles.iam.identity.api.dto.UpdateUserRequest
import com.aibles.iam.identity.api.dto.UserResponse
import com.aibles.iam.identity.usecase.ChangeUserStatusUseCase
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.identity.usecase.DeleteUserUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.identity.usecase.UpdateUserUseCase
import com.aibles.iam.shared.response.ApiResponse
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1/users")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Users", description = "User lifecycle management")
class UsersController(
    private val getUserUseCase: GetUserUseCase,
    private val createUserUseCase: CreateUserUseCase,
    private val updateUserUseCase: UpdateUserUseCase,
    private val changeUserStatusUseCase: ChangeUserStatusUseCase,
    private val deleteUserUseCase: DeleteUserUseCase,
) {

    @GetMapping("/{id}")
    fun getUser(@PathVariable id: UUID): ApiResponse<UserResponse> {
        val user = getUserUseCase.execute(GetUserUseCase.Query(id))
        return ApiResponse.ok(UserResponse.from(user))
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    fun createUser(@Valid @RequestBody request: CreateUserRequest): ApiResponse<UserResponse> {
        val result = createUserUseCase.execute(
            CreateUserUseCase.Command(request.email, request.displayName, googleSub = null)
        )
        return ApiResponse.ok(UserResponse.from(result.user))
    }

    @PatchMapping("/{id}")
    fun updateUser(
        @PathVariable id: UUID,
        @Valid @RequestBody request: UpdateUserRequest,
    ): ApiResponse<UserResponse> {
        val result = updateUserUseCase.execute(UpdateUserUseCase.Command(id, request.displayName))
        return ApiResponse.ok(UserResponse.from(result.user))
    }

    @PatchMapping("/{id}/status")
    fun changeStatus(
        @PathVariable id: UUID,
        @Valid @RequestBody request: ChangeStatusRequest,
    ): ApiResponse<UserResponse> {
        val result = changeUserStatusUseCase.execute(ChangeUserStatusUseCase.Command(id, request.status))
        return ApiResponse.ok(UserResponse.from(result.user))
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun deleteUser(@PathVariable id: UUID) {
        deleteUserUseCase.execute(DeleteUserUseCase.Command(id))
    }
}
