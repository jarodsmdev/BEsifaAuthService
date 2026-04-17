package com.evecta.auth.service;

import com.evecta.auth.dto.user.UserCreateDTO;
import com.evecta.auth.model.UserEntity;

public interface IUserService {
    UserEntity createUser(UserCreateDTO userDTO);
    UserEntity findActiveUserByRut(String rut);
}
