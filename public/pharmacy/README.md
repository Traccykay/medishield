# public/pharmacy/

Pharmacy pages. Pharmacists work only from pending prescriptions whose encounter is
currently assigned to pharmacy, decrypt the medication details needed for dispensing,
then record a dispensed/refused outcome. Refusals require remarks and atomically
return the encounter to its assigned doctor; sibling prescriptions are withheld from
the pharmacy queue until that review occurs.
