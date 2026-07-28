<table class="ms-table">
    <thead><tr><th>Charge</th><th>Unit price</th><th>Quantity</th><th>Line total</th></tr></thead>
    <tbody>
    <?php foreach ($bill['charges'] as $charge) { ?>
        <tr>
            <td><?= e((string) $charge['description_snapshot']) ?></td>
            <td>KES <?= e(number_format((int) $charge['unit_price_snapshot'])) ?></td>
            <td><?= e((string) $charge['quantity']) ?></td>
            <td>KES <?= e(number_format((int) $charge['line_total'])) ?></td>
        </tr>
    <?php } ?>
    </tbody>
</table>
<p><strong>Total: KES <?= e(number_format((int) $bill['total_amount'])) ?></strong></p>
