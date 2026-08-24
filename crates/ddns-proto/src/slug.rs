use rand::Rng;
use rand::seq::IndexedRandom;

pub const ADJECTIVES: &[&str] = &[
    "amber", "brisk", "calm", "daring", "eager", "fancy", "gentle", "happy", "ivory", "jolly",
    "keen", "lively", "mellow", "noble", "orange", "plucky", "quick", "rustic", "silky", "tidy",
    "upbeat", "vivid", "witty", "young", "zesty", "bold", "crisp", "drowsy", "frosty", "golden",
    "hazy", "ironic", "jazzy", "kosher", "lucid", "merry", "neat", "opulent", "peppy", "quaint",
];

pub const ANIMALS: &[&str] = &[
    "otter", "badger", "fox", "wolf", "lynx", "falcon", "heron", "panda", "koala", "lemur",
    "marten", "newt", "ocelot", "puffin", "quokka", "raccoon", "seal", "toucan", "urchin", "viper",
    "walrus", "yak", "zebra", "beaver", "cougar", "dingo", "eagle", "ferret", "gecko", "hamster",
    "ibis", "jackal", "kiwi", "llama", "mole", "narwhal", "oriole", "platypus", "quail", "rabbit",
];

pub fn random_slug(rng: &mut impl Rng) -> String {
    let adjective = ADJECTIVES.choose(rng).expect("wordlists are non-empty");
    let animal = ANIMALS.choose(rng).expect("wordlists are non-empty");
    let hex = rng.random_range(0..256);
    // 40 × 40 × 256 × 65_536 ≈ 2.7e10 combinations — small enough to stay
    // human-readable, large enough that live-tunnel enumeration is not
    // practical and collisions under churn are rare.
    let extra = rng.random_range(0..65536);
    format!("{adjective}-{animal}-{hex:02x}-{extra:04x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn slug_matches_pattern() {
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..500 {
            let slug = random_slug(&mut rng);
            let parts: Vec<&str> = slug.split('-').collect();
            assert_eq!(parts.len(), 4, "slug {slug:?} must have 4 parts");
            assert!(ADJECTIVES.contains(&parts[0]), "bad adjective in {slug:?}");
            assert!(ANIMALS.contains(&parts[1]), "bad animal in {slug:?}");
            assert_eq!(parts[2].len(), 2, "hex part wrong length in {slug:?}");
            assert_eq!(parts[3].len(), 4, "extra hex part wrong length in {slug:?}");
            assert!(
                u8::from_str_radix(parts[2], 16).is_ok(),
                "bad hex in {slug:?}"
            );
            assert!(
                u16::from_str_radix(parts[3], 16).is_ok(),
                "bad extra hex in {slug:?}"
            );
        }
    }

    #[test]
    fn slug_is_deterministic_for_seed() {
        let mut a = StdRng::seed_from_u64(99);
        let mut b = StdRng::seed_from_u64(99);
        for _ in 0..100 {
            assert_eq!(random_slug(&mut a), random_slug(&mut b));
        }
    }

    #[test]
    fn slug_varies_across_seed() {
        let mut a = StdRng::seed_from_u64(1);
        let mut b = StdRng::seed_from_u64(2);
        let sa: Vec<String> = (0..50).map(|_| random_slug(&mut a)).collect();
        let sb: Vec<String> = (0..50).map(|_| random_slug(&mut b)).collect();
        assert!(sa != sb, "two seeds produced identical slug sequences");
    }

    #[test]
    fn wordlists_are_lowercase_ascii() {
        for w in ADJECTIVES.iter().chain(ANIMALS.iter()) {
            assert!(
                w.bytes().all(|b| b.is_ascii_lowercase()),
                "word {w:?} not lowercase"
            );
            assert!(
                w.bytes().all(|b| b.is_ascii_alphabetic()),
                "word {w:?} has non-alpha"
            );
        }
    }
}
