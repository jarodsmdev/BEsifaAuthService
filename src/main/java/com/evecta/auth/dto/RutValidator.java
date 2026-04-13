package com.evecta.auth.dto;

public class RutValidator {

    public static boolean validarRut(String rut, String dv) {
        if (rut == null || dv == null || rut.isEmpty() || dv.isEmpty()) {
            return false;
        }

        // Limpiar el RUT
        rut = rut.replaceAll("[.-]", "");

        // Validar que sean solo números
        if (!rut.matches("\\d+")) {
            return false;
        }

        int suma = 0;
        int multiplicador = 2;

        for (int i = rut.length() - 1; i >= 0; i--) {
            suma += Character.getNumericValue(rut.charAt(i)) * multiplicador;
            multiplicador = multiplicador == 7 ? 2 : multiplicador + 1;
        }

        int resto = suma % 11;
        int digitoEsperado = 11 - resto;

        if (digitoEsperado == 11) return dv.equals("0");
        if (digitoEsperado == 10) return dv.equalsIgnoreCase("K");
        return dv.equals(String.valueOf(digitoEsperado));
    }
}