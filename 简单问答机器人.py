from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import os

model_path = './local-sbert-model'
model_name = 'paraphrase-multilingual-MiniLM-L12-v2'

# 1. Load local model, or download and save if not present
if os.path.exists(model_path):
    print('Loading local model...')
    model = SentenceTransformer(model_path)
else:
    print('First run, downloading and saving model...')
    model = SentenceTransformer(model_name)
    model.save(model_path)
    print('Model saved locally. Next time will be loaded offline.')

# 2. Knowledge base: human anatomy, biology, medical science
knowledge = {
    "What is the function of the heart?": """The heart pumps blood throughout the body, supplying oxygen and nutrients to tissues and removing carbon dioxide and wastes.""",
    "人体有多少块骨头？": '''成年人体内有206块骨头，儿童骨头数量更多，随着成长部分骨头会融合。''',
    "What is the largest organ in the human body?": '''The largest organ in the human body is the skin.''',
    "大脑的主要功能是什么？": '''大脑负责思考、感知、运动控制以及协调身体各项功能，是人体的中枢神经系统的核心。''',
    "What do white blood cells do?": """White blood cells are part of the immune system and help protect the body against infections.""",
    "血液由哪些成分组成？": '''血液主要由红细胞、白细胞、血小板和血浆组成。''',
}

question_list = list(knowledge.keys())
answer_list = list(knowledge.values())

# 3. Encode questions and build faiss index
print("Building semantic index...")
question_embeddings = model.encode(question_list, convert_to_numpy=True, show_progress_bar=True)
faiss.normalize_L2(question_embeddings)
dimension = question_embeddings.shape[1]
index = faiss.IndexFlatIP(dimension)
index.add(question_embeddings)

# 4. Query function
def search_answer(query, top_k=1):
    query_embedding = model.encode([query], convert_to_numpy=True)
    faiss.normalize_L2(query_embedding)
    distances, indices = index.search(query_embedding, top_k)
    results = []
    for idx, score in zip(indices[0], distances[0]):
        results.append({
            "question": question_list[idx],
            "answer": answer_list[idx],
            "score": float(score)
        })
    return results

# 5. Main loop
print("Welcome to the QA search system! Type exit or 退出 to quit.")
while True:
    user_input = input("Please enter your question: ")
    if user_input.strip().lower() in ["exit", "退出"]:
        print("Goodbye!")
        break
    results = search_answer(user_input, top_k=1)
    best = results[0]
    print(f"\nMost relevant knowledge:\nQ: {best['question']}\nA: {best['answer']}\nSimilarity: {best['score']:.4f}\n")
