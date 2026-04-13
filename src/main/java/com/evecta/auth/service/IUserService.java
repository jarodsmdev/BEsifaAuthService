package com.evecta.auth.service;

import com.evecta.auth.dto.UserCreateDTO;
import com.evecta.auth.model.UserEntity;

public interface IUserService {
    UserEntity createUser(UserCreateDTO userDTO);
    UserEntity findActiveUserByRut(String rut);
}
