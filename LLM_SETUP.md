# LLM Integration Setup Guide

This guide explains how to set up the LLM (Large Language Model) integration for AI-powered anomaly analysis using ChatGPT.

## Prerequisites

1. **OpenAI API Account**: You need an OpenAI account with API access
2. **API Key**: Generate an API key from your OpenAI dashboard
3. **Credits**: Ensure you have sufficient API credits/quota

## Configuration Options

### Method 1: Environment Variable (Recommended)

Set the OpenAI API key as an environment variable:

```bash
export OPENAI_API_KEY="your-openai-api-key-here"
```

### Method 2: OpenSearch Dashboards Configuration

Add the following to your `opensearch_dashboards.yml` configuration file:

```yaml
anomaly_detection_dashboards:
  enabled: true
  llm:
    enabled: true
    openai:
      apiKey: "your-openai-api-key-here"
      model: "gpt-4"          # Options: gpt-4, gpt-3.5-turbo
      maxTokens: 800          # Maximum response length
      temperature: 0.3        # Response creativity (0.0-1.0)
```

## Configuration Parameters

| Parameter | Description | Default | Options |
|-----------|-------------|---------|---------|
| `llm.enabled` | Enable/disable LLM analysis | `false` | `true`, `false` |
| `llm.openai.apiKey` | Your OpenAI API key | - | String |
| `llm.openai.model` | ChatGPT model to use | `gpt-4` | `gpt-4`, `gpt-3.5-turbo` |
| `llm.openai.maxTokens` | Maximum response tokens | `800` | 1-4096 |
| `llm.openai.temperature` | Response creativity | `0.3` | 0.0-1.0 |

## Model Recommendations

### GPT-4
- **Best for**: Complex log analysis, detailed insights
- **Cost**: Higher per token
- **Speed**: Slower response time
- **Quality**: Highest analysis quality

### GPT-3.5-turbo
- **Best for**: Quick analysis, cost-effective
- **Cost**: Lower per token
- **Speed**: Faster response time
- **Quality**: Good analysis quality

## Cost Considerations

- **GPT-4**: ~$0.03 per 1K tokens (input) + $0.06 per 1K tokens (output)
- **GPT-3.5-turbo**: ~$0.001 per 1K tokens (input) + $0.002 per 1K tokens (output)
- **Typical analysis**: ~500-1000 tokens per request
- **Estimated cost**: $0.02-0.10 per analysis (GPT-4), $0.001-0.005 per analysis (GPT-3.5-turbo)

## Security Best Practices

1. **API Key Security**:
   - Never commit API keys to version control
   - Use environment variables in production
   - Rotate keys regularly

2. **Network Security**:
   - Ensure HTTPS connections to OpenAI
   - Consider using a proxy for additional security

3. **Data Privacy**:
   - Review OpenAI's data usage policies
   - Consider data sensitivity before enabling
   - Logs are sent to OpenAI for analysis

## Usage

Once configured:

1. Navigate to the **Anomaly Occurrences** table
2. Look for the **AI Insights** column
3. Click **Analyze** button for any anomaly
4. Wait for the analysis to complete
5. Click **View Analysis** to see the results

## Troubleshooting

### Common Issues

1. **"OpenAI API key not configured"**
   - Ensure API key is set in config or environment
   - Restart OpenSearch Dashboards after configuration changes

2. **"LLM analysis is not enabled"**
   - Set `llm.enabled: true` in configuration
   - Restart OpenSearch Dashboards

3. **"OpenAI API quota exceeded"**
   - Check your OpenAI account usage and billing
   - Add more credits to your account

4. **API timeout errors**
   - Check network connectivity
   - Verify API key is valid and active

### Debug Mode

Enable debug logging by adding to your configuration:

```yaml
logging:
  loggers:
    - name: plugins.anomaly-detection-dashboards-plugin
      level: debug
```

## Example Configuration File

Complete example `opensearch_dashboards.yml`:

```yaml
# OpenSearch Dashboards Configuration
opensearch.hosts: ["https://localhost:9200"]

# Anomaly Detection Plugin Configuration
anomaly_detection_dashboards:
  enabled: true
  llm:
    enabled: true
    openai:
      model: "gpt-3.5-turbo"  # Use cheaper model for testing
      maxTokens: 500          # Shorter responses for cost control
      temperature: 0.2        # More focused responses
      # API key should be set via environment variable
```

## Support

For issues related to:
- **OpenAI API**: Contact OpenAI support
- **Plugin Integration**: Check OpenSearch Dashboards logs
- **Configuration**: Refer to this guide

## Rate Limiting

OpenAI has rate limits based on your account tier:
- **Free tier**: 3 requests/minute
- **Pay-as-you-go**: 3,500 requests/minute
- **Consider implementing client-side throttling for high-volume usage**
