<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Guards the shared UI shell's accessibility and responsive-design contract.
 *
 * These are source-level assertions because the shell is a deliberately small
 * PHP view helper with no browser-side runtime. End-to-end tests remain
 * responsible for proving that the rendered pages work in a real browser.
 */
final class SharedUiShellTest extends TestCase
{
    private string $layout;
    private string $stylesheet;

    protected function setUp(): void
    {
        $root = dirname(__DIR__, 2);
        $this->layout = (string) file_get_contents($root . '/includes/layout.php');
        $this->stylesheet = (string) file_get_contents($root . '/public/assets/css/style.css');
    }

    public function testAuthenticatedShellExposesKeyboardAndNavigationLandmarks(): void
    {
        self::assertStringContainsString('class="ms-skip-link"', $this->layout);
        self::assertStringContainsString('id=\\"main-content\\"', $this->layout);
        self::assertStringContainsString('aria-current="page"', $this->layout);
        self::assertStringContainsString('class="ms-sidebar-label"', $this->layout);
        self::assertSame(2, substr_count($this->layout, 'id=\\"main-content\\" tabindex=\\"-1\\"'));
    }

    public function testAlertsAnnounceValidationAndCompletionMessages(): void
    {
        self::assertStringContainsString("\$role = \$type === 'danger' ? 'alert' : 'status';", $this->layout);
        self::assertStringContainsString("aria-live=\"' . \$live", $this->layout);
        self::assertStringContainsString('aria-atomic="true"', $this->layout);
    }

    public function testSharedStylesheetUrlIsCacheBustedWhenTheFileChanges(): void
    {
        self::assertStringContainsString('filemtime($stylesheet)', $this->layout);
        self::assertStringContainsString("'/assets/css/style.css?v='", $this->layout);
        self::assertSame(2, substr_count($this->layout, 'e(layout_stylesheet_url())'));
    }

    public function testStylesheetSupportsAccessibleResponsiveInteraction(): void
    {
        self::assertStringContainsString(':focus-visible', $this->stylesheet);
        self::assertStringContainsString('position: sticky', $this->stylesheet);
        self::assertStringContainsString('@media (prefers-reduced-motion: reduce)', $this->stylesheet);
        self::assertStringContainsString('@media print', $this->stylesheet);
        self::assertStringContainsString('min-height: 44px', $this->stylesheet);
        self::assertStringContainsString('@media (forced-colors: active)', $this->stylesheet);
        self::assertStringContainsString('.ms-sr-only', $this->stylesheet);
        self::assertStringContainsString('font-size: 16px', $this->stylesheet);
    }


    public function testCompactListFiltersHaveProgrammaticLabels(): void
    {
        $root = dirname(__DIR__, 2);
        foreach ([
            'public/admin/users.php',
            'public/patients.php',
            'public/lab/requests.php',
            'public/pharmacy/prescriptions.php',
            'public/reports.php',
        ] as $path) {
            $source = (string) file_get_contents($root . '/' . $path);
            self::assertStringContainsString('ms-sr-only', $source, $path);
        }
    }

    public function testEveryRoleDashboardUsesTheSharedAttentionFirstPattern(): void
    {
        $root = dirname(__DIR__, 2);
        $dashboards = [
            'admin',
            'reception',
            'nurse',
            'doctor',
            'lab',
            'pharmacy',
            'patient',
        ];

        foreach ($dashboards as $role) {
            $source = (string) file_get_contents($root . '/public/' . $role . '/dashboard.php');
            self::assertStringContainsString('ms-dashboard-hero', $source, $role);
            self::assertStringContainsString('ms-dashboard-kicker', $source, $role);
            self::assertStringContainsString('ms-dashboard-heading', $source, $role);
        }

        self::assertStringContainsString('ms-work-queue', $this->stylesheet);
        self::assertStringContainsString('ms-empty-state', $this->stylesheet);
        self::assertStringContainsString('ms-stat-attention', $this->stylesheet);
    }

    public function testClinicalAndBillingViewsUseReadableCardContracts(): void
    {
        $root = dirname(__DIR__, 2);
        $labs = (string) file_get_contents($root . '/public/patient/lab_results.php');
        $prescriptions = (string) file_get_contents($root . '/public/patient/prescriptions.php');
        $bill = (string) file_get_contents($root . '/includes/partials/bill_charges.php');

        self::assertStringContainsString('ms-result-card', $labs);
        self::assertStringContainsString('ms-prescription-card', $prescriptions);
        self::assertStringContainsString('ms-invoice-lines', $bill);
        self::assertStringContainsString('ms-invoice-total', $bill);
        self::assertStringContainsString('ms-status-pill', $this->stylesheet);
    }
}
