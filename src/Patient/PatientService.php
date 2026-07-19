<?php

declare(strict_types=1);

namespace MediShield\Patient;

use MediShield\Auth\Rbac;
use MediShield\Auth\UserRepository;

/**
 * Validation and authorization layer for patient demographics and assignments.
 *
 * This is the object-level access backbone required by the spec: patients can
 * see only their own linked record, nurses/doctors can see assigned patients, and
 * admins can manage demographics/assignments without gaining clinical privileges.
 */
final class PatientService
{
    private const GENDERS = ['male', 'female', 'other'];

    public function __construct(
        private PatientRepository $patients,
        private UserRepository $users
    ) {
    }

    /**
     * Validate and create a patient demographic record.
     *
     * @param array<string,mixed> $input
     * @return array{ok:bool, errors:string[], patient_id:?int}
     */
    public function registerPatient(array $input): array
    {
        $userIdRaw = trim((string) ($input['user_id'] ?? ''));
        $patientNumber = trim((string) ($input['patient_number'] ?? ''));
        $fullName = trim((string) ($input['full_name'] ?? ''));
        $dateOfBirth = trim((string) ($input['date_of_birth'] ?? ''));
        $gender = trim((string) ($input['gender'] ?? ''));
        $phone = $this->nullableText($input['phone'] ?? null, 30);
        $address = $this->nullableText($input['address'] ?? null, 255);
        $emergency = $this->nullableText($input['emergency_contact'] ?? null, 150);
        $errors = [];
        $userId = null;

        if ($patientNumber === '') {
            $errors[] = 'Patient number is required.';
        } elseif (mb_strlen($patientNumber) > 50) {
            $errors[] = 'Patient number must be 50 characters or fewer.';
        } elseif ($this->patients->patientNumberExists($patientNumber)) {
            $errors[] = 'A patient with this patient number already exists.';
        }

        if ($fullName === '') {
            $errors[] = 'Full name is required.';
        } elseif (mb_strlen($fullName) > 150) {
            $errors[] = 'Full name must be 150 characters or fewer.';
        }

        if (!$this->isValidDate($dateOfBirth)) {
            $errors[] = 'Date of birth must use YYYY-MM-DD.';
        }

        if (!in_array($gender, self::GENDERS, true)) {
            $errors[] = 'Gender must be male, female, or other.';
        }

        if ($phone !== null && !$this->isKenyanMobileNumber($phone)) {
            $errors[] = 'Phone must be a valid Kenyan mobile number.';
        }

        if ($emergency !== null && !$this->containsKenyanMobileNumber($emergency)) {
            $errors[] = 'Emergency contact must contain a valid Kenyan mobile number.';
        }

        if ($userIdRaw !== '') {
            if (filter_var($userIdRaw, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) === false) {
                $errors[] = 'Linked account must be an existing patient user.';
            } else {
                $userId = (int) $userIdRaw;
                $user = $this->users->findById($userId);
                if ($user === null || (string) $user['role'] !== Rbac::ROLE_PATIENT) {
                    $errors[] = 'Linked account must be an existing patient user.';
                } elseif ($this->patients->userLinkExists($userId)) {
                    $errors[] = 'That patient account is already linked to a patient record.';
                }
            }
        }

        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'patient_id' => null];
        }

        $patientId = $this->patients->create([
            'user_id' => $userId,
            'patient_number' => $patientNumber,
            'full_name' => $fullName,
            'date_of_birth' => $dateOfBirth,
            'gender' => $gender,
            'phone' => $phone,
            'address' => $address,
            'emergency_contact' => $emergency,
        ]);

        return ['ok' => true, 'errors' => [], 'patient_id' => $patientId];
    }

    /**
     * Assign a patient to a nurse or doctor.
     *
     * @return array{ok:bool, errors:string[]}
     */
    public function assignPatient(int $patientId, int $staffUserId, int $assignedBy): array
    {
        $errors = $this->validateAssignmentTargets($patientId, $staffUserId, $assignedBy);
        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors];
        }

        $this->patients->assign($patientId, $staffUserId, $assignedBy);
        return ['ok' => true, 'errors' => []];
    }

    /**
     * Deactivate an assignment. This preserves history instead of deleting rows.
     *
     * @return array{ok:bool, errors:string[]}
     */
    public function unassignPatient(int $patientId, int $staffUserId): array
    {
        if ($this->patients->findById($patientId) === null) {
            return ['ok' => false, 'errors' => ['Patient not found.']];
        }

        $staff = $this->users->findById($staffUserId);
        if ($staff === null || !in_array((string) $staff['role'], [Rbac::ROLE_NURSE, Rbac::ROLE_DOCTOR], true)) {
            return ['ok' => false, 'errors' => ['Assigned staff member not found.']];
        }

        $this->patients->unassign($patientId, $staffUserId);
        return ['ok' => true, 'errors' => []];
    }

    /**
     * Object-level authorization for viewing a patient demographic/profile page.
     *
     * @param array{user_id:int,role:string} $user
     */
    public function canViewPatient(array $user, int $patientId): bool
    {
        $patient = $this->patients->findById($patientId);
        if ($patient === null) {
            return false;
        }

        $role = (string) $user['role'];
        $userId = (int) $user['user_id'];

        if (in_array($role, [Rbac::ROLE_ADMIN, Rbac::ROLE_RECEPTIONIST], true)) {
            return true;
        }

        if ($role === Rbac::ROLE_PATIENT) {
            return isset($patient['user_id']) && $patient['user_id'] !== null && (int) $patient['user_id'] === $userId;
        }

        if (in_array($role, [Rbac::ROLE_NURSE, Rbac::ROLE_DOCTOR], true)) {
            return $this->patients->isAssigned($patientId, $userId);
        }

        return false;
    }

    /**
     * Return the patient_id linked to a patient login, or null.
     */
    public function patientIdForUser(int $userId): ?int
    {
        $patient = $this->patients->findByUserId($userId);
        return $patient !== null ? (int) $patient['patient_id'] : null;
    }

    /**
     * @return string[]
     */
    private function validateAssignmentTargets(int $patientId, int $staffUserId, int $assignedBy): array
    {
        $errors = [];

        if ($this->patients->findById($patientId) === null) {
            $errors[] = 'Patient not found.';
        }

        $staff = $this->users->findById($staffUserId);
        if ($staff === null) {
            $errors[] = 'Staff member not found.';
        } elseif (!in_array((string) $staff['role'], [Rbac::ROLE_NURSE, Rbac::ROLE_DOCTOR], true)) {
            $errors[] = 'Patients may only be assigned to nurses or doctors.';
        }

        $assigner = $this->users->findById($assignedBy);
        if ($assigner === null) {
            $errors[] = 'Assignment creator not found.';
        } elseif ((string) $assigner['role'] !== Rbac::ROLE_ADMIN) {
            $assignerRole = (string) $assigner['role'];
            $staffRole = $staff !== null ? (string) $staff['role'] : '';
            $nurseRoutingToDoctor = $assignerRole === Rbac::ROLE_NURSE
                && $staffRole === Rbac::ROLE_DOCTOR
                && $this->patients->isAssigned($patientId, $assignedBy);

            if (!$nurseRoutingToDoctor) {
                $errors[] = 'Assignments must be created by an administrator, or by an assigned nurse routing the patient to a doctor.';
            }
        }

        return $errors;
    }

    private function nullableText(mixed $value, int $maxLength): ?string
    {
        $text = trim((string) ($value ?? ''));
        if ($text === '') {
            return null;
        }
        return mb_substr($text, 0, $maxLength);
    }

    private function isValidDate(string $value): bool
    {
        $date = \DateTimeImmutable::createFromFormat('!Y-m-d', $value, new \DateTimeZone('UTC'));
        return $date instanceof \DateTimeImmutable && $date->format('Y-m-d') === $value;
    }

    /**
     * Kenyan mobile numbers use 07/01 locally or 254/+254 internationally,
     * followed by eight subscriber digits.
     */
    private function isKenyanMobileNumber(string $value): bool
    {
        return preg_match('/^(?:\+254|254|0)[71]\d{8}$/', $value) === 1;
    }

    /** Emergency contact permits a descriptive name but requires a Kenyan number. */
    private function containsKenyanMobileNumber(string $value): bool
    {
        return preg_match('/(?:^|[\s:,-])(?:\+254|254|0)[71]\d{8}(?:$|[\s,.-])/', $value) === 1;
    }
}
