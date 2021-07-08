# Generated by default/object.tt
package Paws::WAF::TagInfoForResource;
  use Moose;
  has ResourceARN => (is => 'ro', isa => 'Str');
  has TagList => (is => 'ro', isa => 'ArrayRef[Paws::WAF::Tag]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::WAF::TagInfoForResource

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::WAF::TagInfoForResource object:

  $service_obj->Method(Att1 => { ResourceARN => $value, ..., TagList => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::WAF::TagInfoForResource object:

  $result = $service_obj->Method(...);
  $result->Att1->ResourceARN

=head1 DESCRIPTION

This is B<AWS WAF Classic> documentation. For more information, see AWS
WAF Classic
(https://docs.aws.amazon.com/waf/latest/developerguide/classic-waf-chapter.html)
in the developer guide.

B<For the latest version of AWS WAF>, use the AWS WAFV2 API and see the
AWS WAF Developer Guide
(https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html).
With the latest version, AWS WAF has a single set of endpoints for
regional and global use.

Information for a tag associated with an AWS resource. Tags are
key:value pairs that you can use to categorize and manage your
resources, for purposes like billing. For example, you might set the
tag key to "customer" and the value to the customer name or ID. You can
specify one or more tags to add to each AWS resource, up to 50 tags for
a resource.

Tagging is only available through the API, SDKs, and CLI. You can't
manage or view tags through the AWS WAF Classic console. You can tag
the AWS resources that you manage through AWS WAF Classic: web ACLs,
rule groups, and rules.

=head1 ATTRIBUTES


=head2 ResourceARN => Str




=head2 TagList => ArrayRef[L<Paws::WAF::Tag>]





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::WAF>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

