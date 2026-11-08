// Vector similarity for "Similar cards".
//
// Each card becomes a vector of numbers made of five parts. Each part is scaled to length 1, then multiplied by
// the square root of its weight, so in the cosine below every part counts as much as its weight:
//
//   part      dims  weight  how it is filled
//   element    11    3      one dimension per element; a card with two elements shares 1 between them
//   kind        3    2      Pokémon, trainer or energy
//   stage       4    1.5    basic, stage 1, stage 2 or other
//   rarity      2    1.5    a level from 0 (common) to 1 (rarest), turned into an angle (see Angle)
//   price       2    1      the card's price on a log scale from 0 (฿5) to 1 (฿50,000), also as an angle
//
// Two cards are compared with cosine similarity: dot(a, b) / (|a| × |b|). It is 1 when every known part matches
// and falls towards 0 as they differ. A part a card does not have (for example no element on a trainer card)
// stays all zeros, so it neither adds to nor takes from the match.
static class CardVectors
{
    static readonly string[] Elements =
        ["ไฟ", "น้ำ", "หญ้า", "สายฟ้า", "พลังจิต", "ต่อสู้", "ความมืด", "โลหะ", "มังกร", "แฟรี่", "ไร้สี"];

    static readonly string[] Stages = ["พื้นฐาน", "ร่าง 1", "ร่าง 2", "อื่น ๆ"];

    // Card types from the catalog, grouped into the three kinds of card.
    static readonly Dictionary<string, int> Kinds = new()
    {
        ["โปเกมอน"] = 0,
        ["ซัพพอร์ต"] = 1, ["ไอเท็ม"] = 1, ["ไอเท็มติดโปเกมอน"] = 1, ["สเตเดียม"] = 1,
        ["พลังงานพื้นฐาน"] = 2, ["พลังงานพิเศษ"] = 2,
    };

    // Rarity codes from the catalog, from common (0) to rarest (1), roughly in order of their average price.
    // '-' and unknown codes have no level.
    static readonly Dictionary<string, double> RarityLevels = new()
    {
        ["C"] = 0.0, ["U"] = 0.1, ["R"] = 0.2, ["TR"] = 0.25, ["RR"] = 0.3, ["RRR"] = 0.4,
        ["ACE"] = 0.5, ["S"] = 0.5, ["K"] = 0.5, ["A"] = 0.5, ["PR"] = 0.5, ["MA"] = 0.5, ["SSR"] = 0.5, ["Shining"] = 0.5,
        ["AR"] = 0.6, ["CHR"] = 0.6, ["SR"] = 0.75, ["FUR"] = 0.75, ["CSR"] = 0.8,
        ["SAR"] = 0.9, ["UR"] = 0.9, ["HR"] = 1.0, ["BWR"] = 1.0, ["MUR"] = 1.0,
    };

    const double ElementWeight = 3, KindWeight = 2, StageWeight = 1.5, RarityWeight = 1.5, PriceWeight = 1;
    const double LowestPrice = 5, HighestPrice = 50_000;

    // A card for sale is compared at the seller's price.
    public static double[] ToVector(CardListing card) =>
        ToVector(card.CardType, card.Rarity, card.CardStage, card.CardElement, card.CardPrice);

    // A catalog card is compared at its reference price.
    public static double[] ToVector(CatalogCard card) =>
        ToVector(card.CardType, card.Rarity, card.CardStage, card.CardElement, card.ReferencePrice ?? (decimal)LowestPrice);

    // The point in the middle of several cards: the average of their vectors. A search that matches several cards
    // is compared through this one vector.
    public static double[] Average(IReadOnlyList<double[]> vectors)
    {
        var average = new double[vectors[0].Length];
        foreach (var vector in vectors)
        {
            for (var i = 0; i < average.Length; i++)
            {
                average[i] += vector[i] / vectors.Count;
            }
        }
        return average;
    }

    static double[] ToVector(string cardType, string rarityCode, string? cardStage, string? cardElement, decimal cardPrice)
    {
        var card = (CardType: cardType, Rarity: rarityCode, CardStage: cardStage, CardElement: cardElement, CardPrice: cardPrice);
        var elements = new double[Elements.Length];
        var cardElements = (card.CardElement ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var element in cardElements)
        {
            var index = Array.IndexOf(Elements, element);
            if (index >= 0)
            {
                elements[index] = 1;
            }
        }

        var kind = new double[3];
        var kindIndex = Kinds.TryGetValue(card.CardType, out var known) ? known
            // Many catalog cards have no type ('ไม่ระบุ'); one with an element or a stage is a Pokémon.
            : card.CardElement is not null || card.CardStage is not null ? 0
            : -1;
        if (kindIndex >= 0)
        {
            kind[kindIndex] = 1;
        }

        var stage = new double[Stages.Length];
        var stageIndex = Array.IndexOf(Stages, card.CardStage ?? "");
        if (stageIndex >= 0)
        {
            stage[stageIndex] = 1;
        }

        var rarity = RarityLevels.TryGetValue(card.Rarity, out var level) ? Angle(level) : [0, 0];

        var price = Math.Clamp(
            (Math.Log10(Math.Max((double)card.CardPrice, LowestPrice)) - Math.Log10(LowestPrice))
                / (Math.Log10(HighestPrice) - Math.Log10(LowestPrice)),
            0, 1);

        return
        [
            .. Part(elements, ElementWeight),
            .. Part(kind, KindWeight),
            .. Part(stage, StageWeight),
            .. Part(rarity, RarityWeight),
            .. Part(Angle(price), PriceWeight),
        ];
    }

    public static double Cosine(double[] a, double[] b)
    {
        double dot = 0, lengthA = 0, lengthB = 0;
        for (var i = 0; i < a.Length; i++)
        {
            dot += a[i] * b[i];
            lengthA += a[i] * a[i];
            lengthB += b[i] * b[i];
        }
        return lengthA == 0 || lengthB == 0 ? 0 : dot / (Math.Sqrt(lengthA) * Math.Sqrt(lengthB));
    }

    // A value from 0 to 1 as a point on a quarter circle. The cosine between two such points is cos of the gap
    // between their angles, so values close together score near 1 and the two ends score 0. A plain number would
    // not work: in a cosine, 0.1 and 0.9 point the same way.
    static double[] Angle(double value) => [Math.Cos(value * Math.PI / 2), Math.Sin(value * Math.PI / 2)];

    // Scales a part to length 1, then by √weight. An empty part stays all zeros.
    static double[] Part(double[] values, double weight)
    {
        var length = Math.Sqrt(values.Sum((value) => value * value));
        return length == 0 ? values : values.Select((value) => value / length * Math.Sqrt(weight)).ToArray();
    }
}
