<?php

declare(strict_types=1);

namespace MediShield\Clinical;

use MediShield\Auth\DoctorPatientAuthorizer;
use MediShield\Patient\PatientRepository;
use MediShield\Security\Crypto;

/**
 * Application workflow for clinical modules. It validates typed vitals, applies
 * nurse assignment and complete doctor encounter authorization, encrypts clinical
 * payloads, and delegates atomic writes to repository transactions.
 */
final class ClinicalService
{
    private const DOCTOR_AUTHORIZATION_ERROR = 'You are not authorized for this active consultation.';

    public function __construct(
        private ClinicalRepository $clinical,
        private PatientRepository $patients,
        private Crypto $crypto,
        private DoctorPatientAuthorizer $doctorAuthorizer
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

    public function addDiagnosis(int $patientId, int $doctorId, int $visitId, string $diagnosis, ?string $treatment): array
    {
        if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId)) {
            return [
                'ok' => false,
                'errors' => [self::DOCTOR_AUTHORIZATION_ERROR],
                'record_id' => null,
            ];
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

        $recordId = $this->clinical->transactional(function () use (
            $patientId,
            $doctorId,
            $visitId,
            $diagnosis,
            $treatment
        ): ?int {
            if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId, true)) {
                return null;
            }

            return $this->clinical->createMedicalRecord(
                $visitId,
                $patientId,
                $doctorId,
                $this->crypto->encrypt($diagnosis),
                $treatment !== null ? $this->crypto->encrypt($treatment) : null
            );
        });
        if ($recordId === null) {
            return [
                'ok' => false,
                'errors' => [self::DOCTOR_AUTHORIZATION_ERROR],
                'record_id' => null,
            ];
        }

        return ['ok' => true, 'errors' => [], 'record_id' => $recordId];
    }

    /**
     * Create an encounter-bound clinical record and all of its selected orders.
     * Catalog values are resolved here so a forged browser price or name can never
     * be persisted as an order.
     *
     * @param array<int,mixed> $labTests
     * @param array<int,mixed> $medications
     * @return array{ok:bool,errors:string[],record_id:?int,lab_request_ids:int[],prescription_ids:int[]}
     */
    public function submitConsultation(
        int $patientId,
        int $doctorId,
        int $visitId,
        string $diagnosis,
        ?string $treatment,
        array $labTests,
        array $medications
    ): array {
        if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId)) {
            return [
                'ok' => false,
                'errors' => [self::DOCTOR_AUTHORIZATION_ERROR],
                'record_id' => null,
                'lab_request_ids' => [],
                'prescription_ids' => [],
            ];
        }

        $errors = [];
        $diagnosis = trim($diagnosis);
        $treatment = $this->trimOrNull($treatment);
        if ($diagnosis === '') {
            $errors[] = 'Diagnosis is required.';
        }
        if (mb_strlen($diagnosis) > 4000 || ($treatment !== null && mb_strlen($treatment) > 4000)) {
            $errors[] = 'Clinical notes must be 4000 characters or fewer.';
        }

        $labs = $this->validatedLabOrders($labTests, $errors);
        $prescriptions = $this->validatedPrescriptionOrders($medications, $errors);
        if ($errors !== []) {
            return [
                'ok' => false,
                'errors' => array_values(array_unique($errors)),
                'record_id' => null,
                'lab_request_ids' => [],
                'prescription_ids' => [],
            ];
        }

        $created = $this->clinical->transactional(function () use (
            $patientId,
            $doctorId,
            $visitId,
            $diagnosis,
            $treatment,
            $labs,
            $prescriptions
        ): ?array {
            if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId, true)) {
                return null;
            }

            $encryptedPrescriptions = array_map(function (array $prescription): array {
                return [
                    ...$prescription,
                    'medication' => $this->crypto->encrypt($prescription['medication']),
                    'dosage' => $this->crypto->encrypt($prescription['dosage']),
                    'instructions' => $prescription['instructions'] === null
                        ? null
                        : $this->crypto->encrypt($prescription['instructions']),
                ];
            }, $prescriptions);

            return $this->clinical->createConsultation(
                $visitId,
                $patientId,
                $doctorId,
                $this->crypto->encrypt($diagnosis),
                $treatment !== null ? $this->crypto->encrypt($treatment) : null,
                $labs,
                $encryptedPrescriptions
            );
        });
        if ($created === null) {
            return [
                'ok' => false,
                'errors' => [self::DOCTOR_AUTHORIZATION_ERROR],
                'record_id' => null,
                'lab_request_ids' => [],
                'prescription_ids' => [],
            ];
        }

        return ['ok' => true, 'errors' => [], ...$created];
    }

    public function requestLab(int $patientId, int $doctorId, int $visitId, int $recordId, string $testName, ?string $reason): array
    {
        if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId)) {
            return [
                'ok' => false,
                'errors' => [self::DOCTOR_AUTHORIZATION_ERROR],
                'lab_request_id' => null,
            ];
        }

        $errors = [];
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
        $catalogPriceKes = ClinicalCatalog::priceForTest($testName);
        if ($catalogPriceKes === null) {
            $errors[] = 'Select a catalog lab test.';
        }
        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'lab_request_id' => null];
        }

        $created = $this->clinical->transactional(function () use (
            $patientId,
            $doctorId,
            $visitId,
            $recordId,
            $testName,
            $reason,
            $catalogPriceKes
        ): array {
            if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId, true)) {
                return ['error' => self::DOCTOR_AUTHORIZATION_ERROR, 'id' => null];
            }
            $record = $this->clinical->findRecord($recordId, true);
            if (
                $record === null
                || (int) $record['patient_id'] !== $patientId
                || (int) $record['doctor_id'] !== $doctorId
                || (int) $record['visit_id'] !== $visitId
            ) {
                return ['error' => 'Diagnosis record not found for this patient.', 'id' => null];
            }

            return [
                'error' => null,
                'id' => $this->clinical->createLabRequest(
                    $visitId,
                    $patientId,
                    $recordId,
                    $doctorId,
                    $testName,
                    $reason,
                    $catalogPriceKes
                ),
            ];
        });
        if ($created['error'] !== null) {
            return ['ok' => false, 'errors' => [$created['error']], 'lab_request_id' => null];
        }
        return ['ok' => true, 'errors' => [], 'lab_request_id' => $created['id']];
    }

    public function issuePrescription(
        int $patientId,
        int $doctorId,
        int $visitId,
        int $recordId,
        string $medication,
        string $dosage,
        ?string $instructions
    ): array {
        if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId)) {
            return [
                'ok' => false,
                'errors' => [self::DOCTOR_AUTHORIZATION_ERROR],
                'prescription_id' => null,
            ];
        }

        $errors = [];
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
        $catalogPriceKes = ClinicalCatalog::priceForMedication($medication);
        if ($catalogPriceKes === null) {
            $errors[] = 'Select a catalog medication.';
        }
        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'prescription_id' => null];
        }

        $created = $this->clinical->transactional(function () use (
            $patientId,
            $doctorId,
            $visitId,
            $recordId,
            $medication,
            $dosage,
            $instructions,
            $catalogPriceKes
        ): array {
            if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId, true)) {
                return ['error' => self::DOCTOR_AUTHORIZATION_ERROR, 'id' => null];
            }
            $record = $this->clinical->findRecord($recordId, true);
            if (
                $record === null
                || (int) $record['patient_id'] !== $patientId
                || (int) $record['doctor_id'] !== $doctorId
                || (int) $record['visit_id'] !== $visitId
            ) {
                return ['error' => 'Diagnosis record not found for this patient.', 'id' => null];
            }

            return [
                'error' => null,
                'id' => $this->clinical->createPrescription(
                    $visitId,
                    $patientId,
                    $recordId,
                    $doctorId,
                    $this->crypto->encrypt($medication),
                    $this->crypto->encrypt($dosage),
                    $instructions !== null ? $this->crypto->encrypt($instructions) : null,
                    $catalogPriceKes
                ),
            ];
        });
        if ($created['error'] !== null) {
            return ['ok' => false, 'errors' => [$created['error']], 'prescription_id' => null];
        }

        return ['ok' => true, 'errors' => [], 'prescription_id' => $created['id']];
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
        if ($id === null) {
            return ['ok' => false, 'errors' => ['Lab request is not pending.'], 'lab_result_id' => null];
        }

        return ['ok' => true, 'errors' => [], 'lab_result_id' => $id];
    }

    public function dispense(int $prescriptionId, int $pharmacistId, string $status, ?string $remarks): array
    {
        $prescription = $this->clinical->findPrescription($prescriptionId);
        if ($prescription === null || (string) $prescription['status'] !== 'pending') {
            return ['ok' => false, 'errors' => ['Prescription is not pending.'], 'dispensing_id' => null];
        }
        if (!$this->clinical->isActivePharmacist($pharmacistId)) {
            return ['ok' => false, 'errors' => ['Pharmacist not found.'], 'dispensing_id' => null];
        }
        if (!in_array($status, ['dispensed', 'refused'], true)) {
            return ['ok' => false, 'errors' => ['Dispensing status must be dispensed or refused.'], 'dispensing_id' => null];
        }
        $remarks = $this->trimOrNull($remarks);
        if ($status === 'refused' && $remarks === null) {
            return ['ok' => false, 'errors' => ['Refusal remarks are required.'], 'dispensing_id' => null];
        }
        if ($remarks !== null && mb_strlen($remarks) > 2000) {
            return ['ok' => false, 'errors' => ['Remarks must be 2000 characters or fewer.'], 'dispensing_id' => null];
        }

        $id = $this->clinical->recordPharmacyOutcome($prescriptionId, $pharmacistId, $status, $remarks);
        if ($id === null) {
            return ['ok' => false, 'errors' => ['Prescription is not pending.'], 'dispensing_id' => null];
        }

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

    /**
     * @param array<int,mixed> $labTests
     * @param string[] $errors
     * @return array<int,array{test_name:string,reason:?string,catalog_price_kes:int}>
     */
    private function validatedLabOrders(array $labTests, array &$errors): array
    {
        $orders = [];
        foreach ($labTests as $testName) {
            if (!is_string($testName)) {
                $errors[] = 'Select only catalog lab tests.';
                continue;
            }
            $testName = trim($testName);
            $catalogPriceKes = ClinicalCatalog::priceForTest($testName);
            if ($catalogPriceKes === null) {
                $errors[] = 'Select only catalog lab tests.';
                continue;
            }
            if (isset($orders[$testName])) {
                $errors[] = 'Select each lab test only once.';
                continue;
            }
            $orders[$testName] = ['test_name' => $testName, 'reason' => null, 'catalog_price_kes' => $catalogPriceKes];
        }
        return array_values($orders);
    }

    /**
     * @param array<int,mixed> $medications
     * @param string[] $errors
     * @return array<int,array{medication:string,dosage:string,instructions:?string,catalog_price_kes:int}>
     */
    private function validatedPrescriptionOrders(array $medications, array &$errors): array
    {
        $orders = [];
        foreach ($medications as $medication) {
            if (!is_array($medication)) {
                $errors[] = 'Medication selection is invalid.';
                continue;
            }
            $nameValue = $medication['medication'] ?? null;
            $dosageValue = $medication['dosage'] ?? null;
            $instructionsValue = $medication['instructions'] ?? null;
            if (
                !is_string($nameValue)
                || !is_string($dosageValue)
                || ($instructionsValue !== null && !is_string($instructionsValue))
            ) {
                $errors[] = 'Medication selection is invalid.';
                continue;
            }
            $name = trim($nameValue);
            $dosage = trim($dosageValue);
            $instructions = $this->trimOrNull($instructionsValue);
            $catalogPriceKes = ClinicalCatalog::priceForMedication($name);
            if ($catalogPriceKes === null) {
                $errors[] = 'Select only catalog medications.';
            }
            if ($dosage === '') {
                $errors[] = 'Dosage is required for every selected medication.';
            }
            if (mb_strlen($dosage) > 1000 || ($instructions !== null && mb_strlen($instructions) > 2000)) {
                $errors[] = 'Prescription fields are too long.';
            }
            if ($catalogPriceKes === null || $dosage === '' || mb_strlen($dosage) > 1000 || ($instructions !== null && mb_strlen($instructions) > 2000)) {
                continue;
            }
            if (isset($orders[$name])) {
                $errors[] = 'Select each medication only once.';
                continue;
            }
            $orders[$name] = [
                'medication' => $name,
                'dosage' => $dosage,
                'instructions' => $instructions,
                'catalog_price_kes' => $catalogPriceKes,
            ];
        }
        return array_values($orders);
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
