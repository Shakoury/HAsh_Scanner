import pandas as pd

df = pd.read_csv('phishing_urls.csv')

print("="*70)
print("CHECKING WHAT'S ACTUALLY IN THE DATASET")
print("="*70)

# Count each label
print(f"\nTotal URLs: {len(df)}")
print(f"Label counts:")
print(df['Label'].value_counts())

print("\n" + "="*70)
print("SAMPLE 'bad' URLs (supposed to be PHISHING):")
print("="*70)
bad_urls = df[df['Label'] == 'bad']['URL'].head(20)
for i, url in enumerate(bad_urls, 1):
    print(f"{i:2}. {url}")

print("\n" + "="*70)
print("SAMPLE 'good' URLs (supposed to be LEGITIMATE):")
print("="*70)
good_urls = df[df['Label'] == 'good']['URL'].head(20)
for i, url in enumerate(good_urls, 1):
    print(f"{i:2}. {url}")

print("\n" + "="*70)
print("YOUR ANALYSIS:")
print("="*70)
print("Look at the 'good' URLs above.")
print("Do they look like REAL legitimate sites?")
print("Or do they ALL look like scams?")
print("\nIf they're ALL scams, then the dataset labels are WRONG!")
