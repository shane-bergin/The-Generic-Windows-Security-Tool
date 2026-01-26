using Microsoft.ML.OnnxRuntimeGenAI;
using System;
using System.IO;
using System.Text;

namespace TGWST.Core.Services
{
    public class LocalIntelligence
    {
        private readonly Model _model;
        private readonly Tokenizer _tokenizer;

        public LocalIntelligence()
        {
            // Configure the model to use the DirectML backend
            var modelPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Models");
            _model = new Model(modelPath);
            _tokenizer = new Tokenizer(_model);
        }

        public string Analyze(string prompt)
        {
            var sequences = _tokenizer.Encode(prompt);

            using var generatorParams = new GeneratorParams(_model);
            generatorParams.SetSearchOption("max_length", 2048);

            using var generator = new Generator(_model, generatorParams);
            generator.AppendTokenSequences(sequences);

            using var tokenizerStream = _tokenizer.CreateStream();
            var output = new StringBuilder();

            while (!generator.IsDone())
            {
                generator.GenerateNextToken();
                var token = generator.GetSequence(0)[^1];
                output.Append(tokenizerStream.Decode(token));
            }

            return output.ToString();
        }
    }
}
