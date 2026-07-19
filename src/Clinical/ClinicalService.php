<?php

declare(strict_types=1);

namespace MediShield\Clinical;

use MediShield\Patient\PatientRepository;
use MediShield\Security\Crypto;

/**
 * Application workflow for clinical modules. It validates typed vitals, enforces
 * assigned-patient checks for nurse/doctor actions, encrypts clinical payloads,
 * and delegates queue transitions to repository transactions.
 */
final class ClinicalService
{
    public function __construct(
        private ClinicalRepository $clinical,
        private PatientRepository $patients,
        private Crypto $crypto
    ) {
    }

    public function recordVitals(int $patientId, int $nurseId, array $input): array
    {
        if (!$this->patients->isAssigned($patientId, $nurseId)) {
            return ['ok' => false, 'errors' => ['You are not assigned to this patient.'], 'vitals_id' => null];
        }

        $errors = [];
        $temperature = $this->decimal($input['temperature_c'] ?? null, 30.0, 45.0, 'Temperature', $errors);
        $systolic = $this->integer($input['systolic_mmhg'] ?? null, 50, 300, 'Systolic pressure', $errors);
        $diastolic = $this->integer($input['diastolic_mmhg'] ?? null, 30, 200, 'Diastolic pressure', $errors);
        $pulse = $this->integer($input['pulse_bpm'] ?? null, 20, 250, 'Pulse', $errors);
        $weight = $this->decimal($input['weight_kg'] ?? null, 0.5, 500.0, 'Weight', $errors);
        $symptoms = $this->optionalText($input['symptoms'] ?? null, 2000, 'Symptoms', $errors);

        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'vitals_id' => null];
        }

        $id = $this->clinical->createVitals([
            'patient_id' => $patientId,
            'nurse_id' => $nurseId,
            'temperature_encrypted' => $this->crypto->encrypt((string) $temperature),
            'systolic_encrypted' => $this->crypto->encrypt((string) $systolic),
            'diastolic_encrypted' => $this->crypto->encrypt((string) $diastolic),
            'pulse_encrypted' => $this->crypto->encrypt((string) $pulse),
            'weight_encrypted' => $this->crypto->encrypt((string) $weight),
            'symptoms_encrypted' => $symptoms === null ? null : $this->crypto->encrypt($symptoms),
        ]);

        return ['ok' => true, 'errors' => [], 'vitals_id' => $id];
    }

    public function addDiagnosis(int $patientId, int $doctorId, string $diagnosis, ?string $treatment): array
    {
        if (!$this->patients->isAssigned($patientId, $doctorId)) {
            return ['ok' => false, 'errors' => ['You are not assigned to this patient.'], 'record_id' => null];
        }

        $diagnosis = trim($diagnosis);
        $treatment = $this->trimOrNull($treatment);
        $errors = [];
        if ($diagnosis === '') {
            $errors[] = 'Diagnosis is required.';
        }
        if (mb_strlen($diagnosis) > 4000 || ($treatment !== null && mb_strlen($treatment) > 4000)) {
            $errors[] = 'Clinical notes must be 4000 characters or fewer.';
        }
        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'record_id' => null];
        }

        $recordId = $this->clinical->createMedicalRecord(
            $patientId,
            $doctorId,
            $this->crypto->encrypt($diagnosis),
            $treatment !== null ? $this->crypto->encrypt($treatment) : null
        );

        return ['ok' => true, 'errors' => [], 'record_id' => $recordId];
    }

    public function requestLab(int $patientId, int $doctorId, int $recordId, string $testName, ?string $reason): array
    {
        $errors = $this->validateDoctorRecord($patientId, $doctorId, $recordId);
        $testName = trim($testName);
        $reason = $this->trimOrNull($reason);
        if ($testName === '') {
            $errors[] = 'Test name is required.';
        } elseif (mb_strlen($testName) > 150) {
            $errors[] = 'Test name must be 150 characters or fewer.';
        }
        if ($reason !== null && mb_strlen($reason) > 2000) {
            $errors[] = 'Reason must be 2000 characters or fewer.';
        }
        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'lab_request_id' => null];
        }

        $id = $this->clinical->createLabRequest($patientId, $recordId, $doctorId, $testName, $reason);
        return ['ok' => true, 'errors' => [], 'lab_request_id' => $id];
    }

    public function issuePrescription(
        int $patientId,
        int $doctorId,
        int $recordId,
        string $medication,
        string $dosage,
        ?string $instructions
    ): array {
        $errors = $this->validateDoctorRecord($patientId, $doctorId, $recordId);
        $medication = trim($medication);
        $dosage = trim($dosage);
        $instructions = $this->trimOrNull($instructions);
        if ($medication === '') {
            $errors[] = 'Medication is required.';
        }
        if ($dosage === '') {
            $errors[] = 'Dosage is required.';
        }
        if (mb_strlen($medication) > 1000 || mb_strlen($dosage) > 1000 || ($instructions !== null && mb_strlen($instructions) > 2000)) {
            $errors[] = 'Prescription fields are too long.';
        }
        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'prescription_id' => null];
        }

        $id = $this->clinical->createPrescription(
            $patientId,
            $recordId,
            $doctorId,
            $this->crypto->encrypt($medication),
            $this->crypto->encrypt($dosage),
            $instructions !== null ? $this->crypto->encrypt($instructions) : null
        );

        return ['ok' => true, 'errors' => [], 'prescription_id' => $id];
    }

    public function uploadLabResult(int $labRequestId, int $labTechId, string $result): array
    {
        $request = $this->clinical->findLabRequest($labRequestId);
        if ($request === null || (string) $request['status'] !== 'pending') {
            return ['ok' => false, 'errors' => ['Lab request is not pending.'], 'lab_result_id' => null];
        }
        $result = trim($result);
        if ($result === '') {
            return ['ok' => false, 'errors' => ['Lab result is required.'], 'lab_result_id' => null];
        }
        if (mb_strlen($result) > 4000) {
            return ['ok' => false, 'errors' => ['Lab result must be 4000 characters or fewer.'], 'lab_result_id' => null];
        }

        $id = $this->clinical->createLabResult(
            $labRequestId,
            (int) $request['patient_id'],
            $labTechId,
            $this->crypto->encrypt($result)
        );
        return ['ok' => true, 'errors' => [], 'lab_result_id' => $id];
    }

    public function dispense(int $prescriptionId, int $pharmacistId, string $status, ?string $remarks): array
    {
        $prescription = $this->clinical->findPrescription($prescriptionId);
        if ($prescription === null || (string) $prescription['status'] !== 'pending') {
            return ['ok' => false, 'errors' => ['Prescription is not pending.'], 'dispensing_id' => null];
        }
        if (!in_array($status, ['dispensed', 'refused'], true)) {
            return ['ok' => false, 'errors' => ['Dispensing status must be dispensed or refused.'], 'dispensing_id' => null];
        }
        $remarks = $this->trimOrNull($remarks);
        if ($remarks !== null && mb_strlen($remarks) > 2000) {
            return ['ok' => false, 'errors' => ['Remarks must be 2000 characters or fewer.'], 'dispensing_id' => null];
        }

        $id = $this->clinical->dispensePrescription(
            $prescriptionId,
            (int) $prescription['patient_id'],
            $pharmacistId,
            $status,
            $remarks
        );
        return ['ok' => true, 'errors' => [], 'dispensing_id' => $id];
    }

    public function decrypt(?string $stored): ?string
    {
        return $stored === null || $stored === '' ? null : $this->crypto->decrypt($stored);
    }

    /**
     * Decrypt vital-sign fields only after the caller has completed its
     * authorization check. Keeping this conversion here prevents a view from
     * accidentally rendering the ciphertext or bypassing GCM integrity checks.
     */
    public function decryptVitals(array $vitals): array
    {
        foreach ($vitals as &$vital) {
            $vital['temperature_c'] = $this->crypto->decrypt((string) $vital['temperature_encrypted']);
            $vital['systolic_mmhg'] = $this->crypto->decrypt((string) $vital['systolic_encrypted']);
            $vital['diastolic_mmhg'] = $this->crypto->decrypt((string) $vital['diastolic_encrypted']);
            $vital['pulse_bpm'] = $this->crypto->decrypt((string) $vital['pulse_encrypted']);
            $vital['weight_kg'] = $this->crypto->decrypt((string) $vital['weight_encrypted']);
            $vital['symptoms'] = $this->decrypt($vital['symptoms_encrypted'] ?? null);
        }
        unset($vital);

        return $vitals;
    }

    private function validateDoctorRecord(int $patientId, int $doctorId, int $recordId): array
    {
        $errors = [];
        if (!$this->patients->isAssigned($patientId, $doctorId)) {
            $errors[] = 'You are not assigned to this patient.';
        }
        $record = $this->clinical->findRecord($recordId);
        if ($record === null || (int) $record['patient_id'] !== $patientId || (int) $record['doctor_id'] !== $doctorId) {
            $errors[] = 'Diagnosis record not found for this patient.';
        }
        return $errors;
    }

    private function decimal(mixed $value, float $min, float $max, string $label, array &$errors): ?float
    {
        $filtered = filter_var($value, FILTER_VALIDATE_FLOAT);
        if ($filtered === false || $filtered < $min || $filtered > $max) {
            $errors[] = $label . ' must be between ' . $min . ' and ' . $max . '.';
            return null;
        }
        return (float) $filtered;
    }

    private function integer(mixed $value, int $min, int $max, string $label, array &$errors): ?int
    {
        $filtered = filter_var($value, FILTER_VALIDATE_INT);
        if ($filtered === false || $filtered < $min || $filtered > $max) {
            $errors[] = $label . ' must be between ' . $min . ' and ' . $max . '.';
            return null;
        }
        return (int) $filtered;
    }

    private function optionalText(mixed $value, int $max, string $label, array &$errors): ?string
    {
        $text = $this->trimOrNull((string) ($value ?? ''));
        if ($text !== null && mb_strlen($text) > $max) {
            $errors[] = $label . ' must be ' . $max . ' characters or fewer.';
        }
        return $text;
    }

    private function trimOrNull(?string $value): ?string
    {
        $text = trim((string) $value);
        return $text === '' ? null : $text;
    }
}
