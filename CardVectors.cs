static class CardVectors
{
    static readonly string[] Elements =
        ["ไฟ", "น้ำ", "หญ้า", "สายฟ้า", "พลังจิต", "ต่อสู้", "ความมืด", "โลหะ", "มังกร", "แฟรี่", "ไร้สี"];

    static readonly Dictionary<string, int> Kinds = new()
    {
        ["โปเกมอน"] = 0,
        ["ซัพพอร์ต"] = 1, ["ไอเท็ม"] = 1, ["ไอเท็มติดโปเกมอน"] = 1, ["สเตเดียม"] = 1,
        ["พลังงานพื้นฐาน"] = 2, ["พลังงานพิเศษ"] = 2,
    };

    static readonly Dictionary<string, double> RarityLevels = new()
    {
        ["C"] = 0.0, ["U"] = 0.1, ["R"] = 0.2, ["TR"] = 0.25, ["RR"] = 0.3, ["RRR"] = 0.4,
        ["ACE"] = 0.5, ["S"] = 0.5, ["K"] = 0.5, ["A"] = 0.5, ["PR"] = 0.5, ["MA"] = 0.5, ["SSR"] = 0.5, ["Shining"] = 0.5,
        ["AR"] = 0.6, ["CHR"] = 0.6, ["SR"] = 0.75, ["FUR"] = 0.75, ["CSR"] = 0.8,
        ["SAR"] = 0.9, ["UR"] = 0.9, ["HR"] = 1.0, ["BWR"] = 1.0, ["MUR"] = 1.0,
    };

    const double ElementWeight = 3, KindWeight = 3, RarityWeight = 0.5;

    public static double[] ToVector(CardListing card) =>
        ToVector(card.CardType, card.Rarity, card.CardStage, card.CardElement);

    public static double[] ToVector(CatalogCard card) =>
        ToVector(card.CardType, card.Rarity, card.CardStage, card.CardElement);

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

    static double[] ToVector(string cardType, string rarityCode, string? cardStage, string? cardElement)
    {
        var card = (CardType: cardType, Rarity: rarityCode, CardStage: cardStage, CardElement: cardElement);
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
            : card.CardElement is not null || card.CardStage is not null ? 0
            : -1;
        if (kindIndex >= 0)
        {
            kind[kindIndex] = 1;
        }

        var rarity = RarityLevels.TryGetValue(card.Rarity, out var level) ? Angle(level) : [0, 0];

        return
        [
            .. Part(elements, ElementWeight),
            .. Part(kind, KindWeight),
            .. Part(rarity, RarityWeight),
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

    static double[] Angle(double value) => [Math.Cos(value * Math.PI / 2), Math.Sin(value * Math.PI / 2)];

    static double[] Part(double[] values, double weight)
    {
        var length = Math.Sqrt(values.Sum((value) => value * value));
        return length == 0 ? values : values.Select((value) => value / length * Math.Sqrt(weight)).ToArray();
    }
}
